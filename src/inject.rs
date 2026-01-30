use std::{
  ffi::CString,
  os::raw::{c_char, c_int},
  ptr::NonNull,
};

use thiserror::Error;

use crate::protocol::{ProtocolError, WFRT_HEADER_LEN, WFRT_MAGIC, encode_wfirt_payload};

const MINIMAL_RADIOTAP: [u8; 8] = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
const MAC_BROADCAST: [u8; 6] = [0xff; 6];

#[derive(Debug, Error)]
pub enum InjectError {
  #[error("device name contains interior NUL")]
  InvalidDeviceName,
  #[error("pcap_handle_open returned null")]
  OpenFailed,
  #[error("pcap_send_frame returned {code}")]
  PcapSend { code: c_int },
  #[error("injected {sent} bytes (expected {expected})")]
  ShortWrite { sent: usize, expected: usize },
  #[error(transparent)]
  Protocol(#[from] ProtocolError),
}

#[repr(C)]
struct PcapHandleRaw {
  _private: [u8; 0],
}

unsafe extern "C" {
  fn pcap_handle_open(
    dev: *const c_char,
    snaplen: c_int,
    promisc: c_int,
    timeout_ms: c_int,
  ) -> *mut PcapHandleRaw;
  fn pcap_handle_close(handle: *mut PcapHandleRaw);
  fn pcap_send_frame(handle: *mut PcapHandleRaw, buf: *const u8, len: usize) -> c_int;
}

pub struct PcapHandle {
  raw: NonNull<PcapHandleRaw>,
}

impl PcapHandle {
  pub fn open(
    dev: &str,
    snaplen: i32,
    promisc: bool,
    timeout_ms: i32,
  ) -> Result<Self, InjectError> {
    let dev_c = CString::new(dev).map_err(|_| InjectError::InvalidDeviceName)?;
    let raw = unsafe {
      pcap_handle_open(
        dev_c.as_ptr(),
        snaplen as c_int,
        if promisc { 1 } else { 0 },
        timeout_ms as c_int,
      )
    };
    let raw = NonNull::new(raw).ok_or(InjectError::OpenFailed)?;
    Ok(Self { raw })
  }

  pub fn send_wfirt(
    &self,
    src: [u8; 6],
    dst: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
  ) -> Result<(), InjectError> {
    let frame = build_wfirt_frame(src, dst, bssid, payload)?;
    let ret = unsafe { pcap_send_frame(self.raw.as_ptr(), frame.as_ptr(), frame.len()) };
    if ret < 0 {
      return Err(InjectError::PcapSend { code: ret });
    }
    if ret as usize != frame.len() {
      return Err(InjectError::ShortWrite {
        sent: ret as usize,
        expected: frame.len(),
      });
    }
    Ok(())
  }
}

impl Drop for PcapHandle {
  fn drop(&mut self) {
    unsafe { pcap_handle_close(self.raw.as_ptr()) };
  }
}

/// Build a minimal QoS Data frame carrying a WFRT payload and send it via libpcap.
///
/// - type/subtype: Data/QoS Data
/// - ToDS/FromDS: 0/0
/// - Addr1: `dst`
/// - Addr2: `src`
/// - Addr3 (BSSID): `bssid`
/// - Seq/frag/QoS control: zeroed
///
/// Radiotap: minimal 8-byte header (no present flags).
pub fn send_wfirt(
  dev: &str,
  src: [u8; 6],
  dst: [u8; 6],
  bssid: [u8; 6],
  payload: &[u8],
) -> Result<(), InjectError> {
  let handle = PcapHandle::open(dev, 4096, true, 1000)?;
  handle.send_wfirt(src, dst, bssid, payload)
}

/// Convenience helper: broadcast RA and BSSID matching `src`.
pub fn send_wfirt_broadcast(dev: &str, src: [u8; 6], payload: &[u8]) -> Result<(), InjectError> {
  send_wfirt(dev, src, MAC_BROADCAST, src, payload)
}

/// Build the on-air frame bytes (radiotap + 802.11 QoS Data + WFRT payload).
pub fn build_wfirt_frame(
  src: [u8; 6],
  dst: [u8; 6],
  bssid: [u8; 6],
  payload: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
  let wfirt = encode_wfirt_payload(payload)?;

  // 802.11 QoS Data header (24 + 2 bytes QoS control)
  // Frame Control: version=0, type=Data(2), subtype=QoS Data(8), flags all zero -> 0x0088 LE
  let mut hdr = Vec::with_capacity(26);
  hdr.extend_from_slice(&0x0088u16.to_le_bytes()); // frame control
  hdr.extend_from_slice(&0u16.to_le_bytes()); // duration
  hdr.extend_from_slice(&dst);
  hdr.extend_from_slice(&src);
  hdr.extend_from_slice(&bssid);
  hdr.extend_from_slice(&0u16.to_le_bytes()); // seq/frag
  hdr.extend_from_slice(&0u16.to_le_bytes()); // QoS control

  let mut frame = Vec::with_capacity(MINIMAL_RADIOTAP.len() + hdr.len() + wfirt.len());
  frame.extend_from_slice(&MINIMAL_RADIOTAP);
  frame.extend_from_slice(&hdr);
  frame.extend_from_slice(&wfirt);
  Ok(frame)
}

/// Parse-only helper to check WFRT framing in tests/examples.
pub fn extract_wfirt(payload: &[u8]) -> Option<&[u8]> {
  if payload.len() < WFRT_HEADER_LEN {
    return None;
  }
  if payload.get(..4)? != WFRT_MAGIC {
    return None;
  }
  let len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
  let start = WFRT_HEADER_LEN;
  let end = start.checked_add(len)?;
  payload.get(start..end)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn build_frame_contains_radiotap_and_header() {
    let src = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let dst = MAC_BROADCAST;
    let bssid = src;
    let payload = b"hello";

    let frame = build_wfirt_frame(src, dst, bssid, payload).expect("build");
    assert!(frame.starts_with(&MINIMAL_RADIOTAP));
    // Frame control is little-endian 0x0088 => bytes [0x88, 0x00] at offset 8
    assert_eq!(&frame[8..10], &[0x88, 0x00]);
    let wfrt_off = MINIMAL_RADIOTAP.len() + 26;
    assert_eq!(&frame[wfrt_off..wfrt_off + 4], b"WFRT");
    assert_eq!(
      extract_wfirt(&frame[wfrt_off..wfrt_off + 6 + payload.len()]),
      Some(&payload[..])
    );
  }
}
