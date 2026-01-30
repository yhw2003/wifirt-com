use ieee80211::{
  GenericFrame,
  common::{FCFFlags, FrameControlField, FrameType, SequenceControl},
  control_frame::ControlFrame,
  data_frame::header::DataFrameHeader,
  mac_parser::MACAddress,
  mgmt_frame::ManagementFrameHeader,
  scroll::ctx::TryFromCtx,
};

use crate::{
  pcap::{PcapError, PcapHandle, RawPacket},
  radiotap::{RtMeta, parse_radiotap},
};

/// Parsed 802.11 header fields we care about for logging/inspection.
pub struct Dot11Meta {
  pub frame_type: FrameType,
  pub flags: FCFFlags,
  pub duration: u16,
  pub address_1: MACAddress,
  pub address_2: Option<MACAddress>,
  pub address_3: Option<MACAddress>,
  pub sequence_control: Option<SequenceControl>,
}

/// Fully-parsed view of a captured 802.11 frame with radiotap metadata.
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

impl PcapHandle {
  /// Blocking capture loop on this handle, invoking `handler` for each parsed 802.11 packet.
  pub fn capture_loop<F>(&mut self, mut handler: F) -> Result<(), PcapError>
  where
    F: for<'a> FnMut(CapturedPacket<'a>),
  {
    loop {
      let Some(raw) = self.next_raw()? else {
        break;
      };
      if let Some(packet) = parse_raw_packet(&raw) {
        handler(packet);
      }
    }
    Ok(())
  }

  /// Spawn a blocking capture loop on a dedicated thread.
  pub async fn capture_async<F>(mut self, handler: F) -> Result<(), PcapError>
  where
    F: for<'a> FnMut(CapturedPacket<'a>) + Send + 'static,
    Self: Send + 'static,
  {
    tokio::task::spawn_blocking(move || self.capture_loop(handler))
      .await
      .map_err(|err| PcapError::CaptureTaskJoin(err.to_string()))?
  }
}

pub async fn run_capture<F>(dev: &str, filter: &str, handler: F) -> Result<(), PcapError>
where
  F: for<'a> FnMut(CapturedPacket<'a>) + Send + 'static,
{
  let mut handle = PcapHandle::open(dev, 4096, true, 1000)?;
  if !filter.is_empty() {
    handle.set_filter(filter)?;
  }

  if let Ok(dlt) = handle.datalink() {
    const DLT_IEEE802_11_RADIO: i32 = 127;
    if dlt != DLT_IEEE802_11_RADIO {
      eprintln!(
        "Warning: datalink type={} (expected {}). Parsing may fail.",
        dlt, DLT_IEEE802_11_RADIO
      );
    }
  }

  handle.capture_async(handler).await
}

fn parse_raw_packet(raw: &RawPacket) -> Option<CapturedPacket<'_>> {
  parse_packet(&raw.data, raw.caplen, raw.len, raw.ts_sec, raw.ts_usec)
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
