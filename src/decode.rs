use ieee80211::{
  common::{FrameType, ManagementFrameSubtype},
  mgmt_frame::body::{BeaconBody, ProbeRequestBody, ProbeResponseBody},
  scroll::ctx::TryFromCtx,
};

use crate::{capture::CapturedPacket, radiotap::freq_to_channel};

const WFRT_MAGIC: &[u8; 4] = b"WFRT";
const WFRT_HEADER_LEN: usize = 6;

pub fn handle_packet(packet: CapturedPacket<'_>) {
  println!("=== Packet ===");
  println!(
    "PCAP: time={}.{:06} caplen={} len={}",
    packet.ts_sec, packet.ts_usec, packet.caplen, packet.len
  );

  let rt = packet.radiotap;
  print!("Radiotap: len={}", packet.radiotap_len);
  if rt.has_dbm_signal {
    print!(" rssi={}dBm", rt.dbm_signal);
  }
  if rt.has_rate {
    let mbps = rt.rate_500kbps as f32 * 0.5;
    print!(" rate={:.1}Mbps", mbps);
  }
  if rt.has_channel {
    let ch = freq_to_channel(rt.chan_freq);
    if ch > 0 {
      print!(" channel={}", ch);
    }
    print!(" freq={}MHz", rt.chan_freq);
  }
  if rt.has_antenna {
    print!(" ant={}", rt.antenna);
  }
  if rt.has_flags {
    print!(" flags=0x{:02x}", rt.rt_flags);
  }
  println!();

  let dot11 = &packet.dot11;
  let flags = dot11.flags;
  let frame_type = dot11.frame_type;

  println!(
    "802.11: type={:?} ToDS={} FromDS={} Retry={} Protected={} PwrMgmt={} MoreData={}",
    frame_type,
    flags.to_ds(),
    flags.from_ds(),
    flags.retry(),
    flags.protected(),
    flags.pwr_mgmt(),
    flags.more_data()
  );

  println!(
    "ADDR: A1={} A2={} A3={}",
    dot11.address_1,
    opt_mac_to_string(dot11.address_2),
    opt_mac_to_string(dot11.address_3)
  );

  let duration = dot11.duration;
  if let Some(seq) = dot11.sequence_control {
    println!(
      "SEQ: seq={} frag={} duration={}",
      seq.sequence_number(),
      seq.fragment_number(),
      duration
    );
  } else {
    println!("SEQ: duration={}", duration);
  }

  if matches!(frame_type, FrameType::Management(_)) {
    print_ssid_if_any(frame_type, packet.payload);
  }

  if let Some(payload) = extract_wifirt_payload(packet.payload) {
    println!("WFRT: len={} bytes", payload.len());
    println!("WFRT: {}", hex_bytes(payload));
  }

  println!();
}

fn opt_mac_to_string(addr: Option<ieee80211::mac_parser::MACAddress>) -> String {
  addr.map_or_else(|| "-".to_string(), |a| a.to_string())
}

fn print_ssid_if_any(frame_type: FrameType, payload: &[u8]) {
  match frame_type {
    FrameType::Management(ManagementFrameSubtype::Beacon) => {
      if let Ok((body, _)) = BeaconBody::try_from_ctx(payload, ()) {
        print_ssid("Beacon", body.ssid());
      }
    }
    FrameType::Management(ManagementFrameSubtype::ProbeResponse) => {
      if let Ok((body, _)) = ProbeResponseBody::try_from_ctx(payload, ()) {
        print_ssid("ProbeResp", body.ssid());
      }
    }
    FrameType::Management(ManagementFrameSubtype::ProbeRequest) => {
      if let Ok((body, _)) = ProbeRequestBody::try_from_ctx(payload, ()) {
        print_ssid("ProbeReq", body.ssid());
      }
    }
    _ => {}
  }
}

fn print_ssid(kind: &str, ssid: Option<&str>) {
  match ssid {
    Some(name) if !name.is_empty() => println!("  SSID({}): {}", kind, name),
    Some(_) => println!("  SSID({}): <hidden>", kind),
    None => {}
  }
}

fn extract_wifirt_payload(payload: &[u8]) -> Option<&[u8]> {
  if payload.len() < WFRT_HEADER_LEN {
    return None;
  }
  if &payload[..WFRT_MAGIC.len()] != WFRT_MAGIC {
    return None;
  }
  let len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
  let start = WFRT_HEADER_LEN;
  let end = start.checked_add(len)?;
  payload.get(start..end)
}

fn hex_bytes(payload: &[u8]) -> String {
  let mut out = String::new();
  for (idx, b) in payload.iter().enumerate() {
    if idx > 0 {
      out.push(' ');
    }
    out.push_str(&format!("{:02x}", b));
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn extract_wifirt_payload_ok() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(WFRT_MAGIC);
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    bytes.extend_from_slice(&[0x11, 0x22]);

    let payload = extract_wifirt_payload(&bytes).expect("payload");
    assert_eq!(payload, [0xde, 0xad, 0xbe, 0xef]);
  }

  #[test]
  fn extract_wifirt_payload_rejects_short() {
    let bytes = [0u8; 5];
    assert!(extract_wifirt_payload(&bytes).is_none());
  }

  #[test]
  fn extract_wifirt_payload_rejects_bad_len() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(WFRT_MAGIC);
    bytes.extend_from_slice(&10u16.to_le_bytes());
    bytes.extend_from_slice(&[0x01, 0x02, 0x03]);
    assert!(extract_wifirt_payload(&bytes).is_none());
  }
}
