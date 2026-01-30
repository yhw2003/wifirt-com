use std::{
  ffi::CString,
  os::raw::{c_char, c_int},
  ptr::NonNull,
  slice,
};

use thiserror::Error;

use crate::protocol::{ProtocolError, WFRT_HEADER_LEN, WFRT_MAGIC, encode_wfirt_payload};

const MINIMAL_RADIOTAP: [u8; 8] = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
const MAC_BROADCAST: [u8; 6] = [0xff; 6];

#[derive(Debug, Error)]
pub enum PcapError {
  #[error("device name contains interior NUL")]
  InvalidDeviceName,
  #[error("filter contains interior NUL")]
  InvalidFilter,
  #[error("pcap_handle_open returned null")]
  OpenFailed,
  #[error("pcap_handle_set_filter failed with code {code}")]
  SetFilterFailed { code: c_int },
  #[error("pcap_handle_get_dlt failed with code {code}")]
  GetDltFailed { code: c_int },
  #[error("pcap_handle_next failed with code {code}")]
  CaptureFailed { code: c_int },
  #[error("capture task failed: {0}")]
  CaptureTaskJoin(String),
  #[error("pcap_send_frame returned {code}")]
  PcapSend { code: c_int },
  #[error("injected {sent} bytes (expected {expected})")]
  ShortWrite { sent: usize, expected: usize },
  #[error(transparent)]
  Protocol(#[from] ProtocolError),
}

#[repr(C)]
pub(crate) struct PcapHandleRaw {
  _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct PcapPacketView {
  pub data: *const u8,
  pub caplen: u32,
  pub len: u32,
  pub ts_sec: u64,
  pub ts_usec: u32,
}

#[derive(Debug)]
pub(crate) struct RawPacket {
  pub data: Vec<u8>,
  pub caplen: u32,
  pub len: u32,
  pub ts_sec: u64,
  pub ts_usec: u32,
}

unsafe extern "C" {
  pub(crate) fn pcap_handle_open(
    dev: *const c_char,
    snaplen: c_int,
    promisc: c_int,
    timeout_ms: c_int,
  ) -> *mut PcapHandleRaw;
  pub(crate) fn pcap_handle_close(handle: *mut PcapHandleRaw);
  pub(crate) fn pcap_handle_set_filter(handle: *mut PcapHandleRaw, filter: *const c_char) -> c_int;
  pub(crate) fn pcap_handle_get_dlt(handle: *const PcapHandleRaw) -> c_int;
  pub(crate) fn pcap_handle_next(handle: *mut PcapHandleRaw, out: *mut PcapPacketView) -> c_int;
  pub(crate) fn pcap_send_frame(handle: *mut PcapHandleRaw, buf: *const u8, len: usize) -> c_int;
}

pub struct PcapHandle {
  raw: NonNull<PcapHandleRaw>,
}

// The underlying pcap_t is used from a single thread at a time; we only move
// the handle between threads (never share), so declaring Send is sound.
unsafe impl Send for PcapHandle {}

impl PcapHandle {
  pub fn open(dev: &str, snaplen: i32, promisc: bool, timeout_ms: i32) -> Result<Self, PcapError> {
    let dev_c = CString::new(dev).map_err(|_| PcapError::InvalidDeviceName)?;
    let raw = unsafe {
      pcap_handle_open(
        dev_c.as_ptr(),
        snaplen as c_int,
        if promisc { 1 } else { 0 },
        timeout_ms as c_int,
      )
    };
    let raw = NonNull::new(raw).ok_or(PcapError::OpenFailed)?;
    Ok(Self { raw })
  }

  pub fn set_filter(&mut self, filter: &str) -> Result<(), PcapError> {
    let filter_c = CString::new(filter).map_err(|_| PcapError::InvalidFilter)?;
    let ret = unsafe { pcap_handle_set_filter(self.raw.as_ptr(), filter_c.as_ptr()) };
    if ret == 0 {
      Ok(())
    } else {
      Err(PcapError::SetFilterFailed { code: ret })
    }
  }

  pub fn datalink(&self) -> Result<i32, PcapError> {
    let ret = unsafe { pcap_handle_get_dlt(self.raw.as_ptr()) };
    if ret < 0 {
      Err(PcapError::GetDltFailed { code: ret })
    } else {
      Ok(ret)
    }
  }

  pub(crate) fn next_raw(&mut self) -> Result<Option<RawPacket>, PcapError> {
    loop {
      let mut view = PcapPacketView {
        data: std::ptr::null(),
        caplen: 0,
        len: 0,
        ts_sec: 0,
        ts_usec: 0,
      };
      let ret = unsafe { pcap_handle_next(self.raw.as_ptr(), &mut view as *mut PcapPacketView) };
      match ret {
        0 => {
          let data = unsafe { slice::from_raw_parts(view.data, view.caplen as usize).to_vec() };
          return Ok(Some(RawPacket {
            data,
            caplen: view.caplen,
            len: view.len,
            ts_sec: view.ts_sec,
            ts_usec: view.ts_usec,
          }));
        }
        1 => continue, // timeout, keep waiting
        -2 => return Ok(None),
        code => return Err(PcapError::CaptureFailed { code }),
      }
    }
  }

  pub fn send_wfirt(
    &self,
    src: [u8; 6],
    dst: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
  ) -> Result<(), PcapError> {
    let frame = build_wfirt_frame(src, dst, bssid, payload)?;
    let ret = unsafe { pcap_send_frame(self.raw.as_ptr(), frame.as_ptr(), frame.len()) };
    if ret < 0 {
      return Err(PcapError::PcapSend { code: ret });
    }
    if ret as usize != frame.len() {
      return Err(PcapError::ShortWrite {
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
) -> Result<(), PcapError> {
  let handle = PcapHandle::open(dev, 4096, true, 1000)?;
  handle.send_wfirt(src, dst, bssid, payload)
}

/// Convenience helper: broadcast RA and BSSID matching `src`.
pub fn send_wfirt_broadcast(dev: &str, src: [u8; 6], payload: &[u8]) -> Result<(), PcapError> {
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
