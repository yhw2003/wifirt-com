use std::{
  ffi::CString,
  os::raw::{c_char, c_int, c_void},
  panic::{self, AssertUnwindSafe},
};

use ieee80211::{
  GenericFrame,
  common::{FCFFlags, FrameControlField, FrameType, SequenceControl},
  control_frame::ControlFrame,
  data_frame::header::DataFrameHeader,
  mac_parser::MACAddress,
  mgmt_frame::ManagementFrameHeader,
  scroll::ctx::TryFromCtx,
};

use crate::radiotap::{RtMeta, parse_radiotap};

type PacketCallback = unsafe extern "C" fn(*const u8, u32, u32, u64, u32, *mut c_void);

pub struct Dot11Meta {
  pub frame_type: FrameType,
  pub flags: FCFFlags,
  pub duration: u16,
  pub address_1: MACAddress,
  pub address_2: Option<MACAddress>,
  pub address_3: Option<MACAddress>,
  pub sequence_control: Option<SequenceControl>,
}

pub struct CapturedPacket<'a> {
  pub payload: &'a [u8],
  pub caplen: u32,
  pub len: u32,
  pub ts_sec: u64,
  pub ts_usec: u32,
  pub radiotap_len: usize,
  pub radiotap: RtMeta,
  pub dot11: Dot11Meta,
}

type PacketHandler = Box<dyn for<'a> FnMut(CapturedPacket<'a>) + Send>;

struct CaptureCtx {
  handler: PacketHandler,
}

unsafe extern "C" {
  fn pcap_start_capture(
    dev: *const c_char,
    filter: *const c_char,
    snaplen: c_int,
    promisc: c_int,
    timeout_ms: c_int,
    cb: PacketCallback,
    user: *mut c_void,
  ) -> c_int;
}

pub async fn run_capture<F>(dev: &str, filter: &str, handler: F)
where
  F: for<'a> FnMut(CapturedPacket<'a>) + Send + 'static,
{
  let dev = dev.to_string();
  let filter = filter.to_string();
  tokio::task::spawn_blocking(move || unsafe {
    let dev_c = CString::new(dev).expect("device has nul");
    let filter_c = CString::new(filter).expect("filter has nul");
    let ctx = Box::new(CaptureCtx {
      handler: Box::new(handler),
    });
    let ctx_ptr = Box::into_raw(ctx) as *mut c_void;
    let ret = pcap_start_capture(
      dev_c.as_ptr(),
      filter_c.as_ptr(),
      4096,
      1,
      1000,
      on_packet,
      ctx_ptr,
    );
    if !ctx_ptr.is_null() {
      drop(Box::from_raw(ctx_ptr as *mut CaptureCtx));
    }
    if ret != 0 {
      eprintln!("pcap_start_capture exited with code {}", ret);
    }
  })
  .await
  .unwrap();
}

unsafe extern "C" fn on_packet(
  data: *const u8,
  caplen: u32,
  len: u32,
  ts_sec: u64,
  ts_usec: u32,
  user: *mut c_void,
) {
  if data.is_null() || caplen == 0 || user.is_null() {
    return;
  }
  let bytes = unsafe { std::slice::from_raw_parts(data, caplen as usize) };
  let ctx = unsafe { &mut *(user as *mut CaptureCtx) };
  if let Some(packet) = parse_packet(bytes, caplen, len, ts_sec, ts_usec) {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
      (ctx.handler)(packet);
    }));
  }
}

fn parse_packet<'a>(
  bytes: &'a [u8],
  caplen: u32,
  len: u32,
  ts_sec: u64,
  ts_usec: u32,
) -> Option<CapturedPacket<'a>> {
  let (rt, rt_len) = parse_radiotap(bytes).ok()?;
  let p80211 = bytes.get(rt_len..)?;
  let generic = GenericFrame::new(p80211, false).ok()?;
  let fcf = generic.frame_control_field();
  let header_len = dot11_header_len(p80211, fcf)?;
  if header_len > p80211.len() {
    return None;
  }

  Some(CapturedPacket {
    payload: &p80211[header_len..],
    caplen,
    len,
    ts_sec,
    ts_usec,
    radiotap_len: rt_len,
    radiotap: rt,
    dot11: Dot11Meta {
      frame_type: fcf.frame_type(),
      flags: fcf.flags(),
      duration: generic.duration(),
      address_1: generic.address_1(),
      address_2: generic.address_2(),
      address_3: generic.address_3(),
      sequence_control: generic.sequence_control(),
    },
  })
}

fn dot11_header_len(p80211: &[u8], fcf: FrameControlField) -> Option<usize> {
  match fcf.frame_type() {
    FrameType::Data(_) => {
      let (_, offset) = DataFrameHeader::try_from_ctx(p80211, ()).ok()?;
      Some(offset)
    }
    FrameType::Management(_) => {
      let body = p80211.get(2..)?;
      let (_, offset) = ManagementFrameHeader::try_from_ctx(body, fcf.flags()).ok()?;
      Some(2 + offset)
    }
    FrameType::Control(subtype) => {
      let body = p80211.get(2..)?;
      let (_, offset) = ControlFrame::try_from_ctx(body, (subtype, fcf.flags())).ok()?;
      Some(2 + offset)
    }
    FrameType::Unknown(_) => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ieee80211::common::{DataFrameSubtype, FrameControlField, FrameType, ManagementFrameSubtype};

  fn radiotap_header() -> [u8; 8] {
    [0, 0, 8, 0, 0, 0, 0, 0]
  }

  fn base_data_header(fcf: FrameControlField) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&fcf.into_bits().to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    bytes.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    bytes.extend_from_slice(&[0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
  }

  #[test]
  fn parse_data_payload() {
    let fcf = FrameControlField::new().with_frame_type(FrameType::Data(DataFrameSubtype::Data));
    let mut p80211 = base_data_header(fcf);
    let payload = [0xde, 0xad, 0xbe, 0xef];
    p80211.extend_from_slice(&payload);

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&radiotap_header());
    pkt.extend_from_slice(&p80211);

    let parsed = parse_packet(&pkt, pkt.len() as u32, pkt.len() as u32, 0, 0).expect("parse");
    assert_eq!(parsed.payload, payload);
    assert!(matches!(parsed.dot11.frame_type, FrameType::Data(_)));
  }

  #[test]
  fn parse_qos_data_payload() {
    let fcf = FrameControlField::new().with_frame_type(FrameType::Data(DataFrameSubtype::QoSData));
    let mut p80211 = base_data_header(fcf);
    p80211.extend_from_slice(&0x1234u16.to_le_bytes()); // QoS control
    let payload = [0x01, 0x02, 0x03];
    p80211.extend_from_slice(&payload);

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&radiotap_header());
    pkt.extend_from_slice(&p80211);

    let parsed = parse_packet(&pkt, pkt.len() as u32, pkt.len() as u32, 0, 0).expect("parse");
    assert_eq!(parsed.payload, payload);
    assert_eq!(parsed.payload, payload);
  }

  #[test]
  fn parse_beacon_payload() {
    let fcf = FrameControlField::new()
      .with_frame_type(FrameType::Management(ManagementFrameSubtype::Beacon));
    let mut p80211 = base_data_header(fcf);
    let mut body = Vec::new();
    body.extend_from_slice(&0u64.to_le_bytes()); // timestamp
    body.extend_from_slice(&100u16.to_le_bytes()); // beacon interval
    body.extend_from_slice(&0u16.to_le_bytes()); // capabilities
    body.extend_from_slice(&[0x00, 0x03, b'a', b'b', b'c']); // SSID element
    p80211.extend_from_slice(&body);

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&radiotap_header());
    pkt.extend_from_slice(&p80211);

    let parsed = parse_packet(&pkt, pkt.len() as u32, pkt.len() as u32, 0, 0).expect("parse");
    assert_eq!(parsed.payload, body);
    assert!(matches!(
      parsed.dot11.frame_type,
      FrameType::Management(ManagementFrameSubtype::Beacon)
    ));
  }
}
