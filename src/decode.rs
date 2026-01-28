use ieee80211::{
  common::FrameType,
  match_frames,
  mgmt_frame::{BeaconFrame, ProbeRequestFrame, ProbeResponseFrame},
  GenericFrame,
};

use crate::radiotap::{freq_to_channel, parse_radiotap};

pub fn handle_packet(bytes: &[u8], caplen: u32, len: u32, ts_sec: u64, ts_usec: u32) {
  println!("=== Packet ===");
  println!(
    "PCAP: time={}.{:06} caplen={} len={}",
    ts_sec, ts_usec, caplen, len
  );

  let Some((rt, rt_len)) = parse_radiotap(bytes) else {
    println!("Radiotap: <parse failed>");
    return;
  };

  print!("Radiotap: len={}", rt_len);
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

  if rt_len >= bytes.len() {
    return;
  }
  let p80211 = &bytes[rt_len..];

  let generic = match GenericFrame::new(p80211, false) {
    Ok(frame) => frame,
    Err(_) => {
      println!("802.11: <parse failed>");
      return;
    }
  };

  let fcf = generic.frame_control_field();
  let flags = fcf.flags();
  let frame_type = fcf.frame_type();

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

  let addr1 = generic.address_1();
  let addr2 = generic.address_2();
  let addr3 = generic.address_3();
  println!(
    "ADDR: A1={} A2={} A3={}",
    addr1,
    opt_mac_to_string(addr2),
    opt_mac_to_string(addr3)
  );

  let duration = generic.duration();
  if let Some(seq) = generic.sequence_control() {
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
    print_ssid_if_any(p80211);
  }

  println!();
}

fn opt_mac_to_string(addr: Option<ieee80211::mac_parser::MACAddress>) -> String {
  addr.map_or_else(|| "-".to_string(), |a| a.to_string())
}

fn print_ssid_if_any(p80211: &[u8]) {
  let _ = match_frames! {
    p80211,
    beacon = BeaconFrame => {
      print_ssid("Beacon", beacon.body.ssid());
    }
    probe_resp = ProbeResponseFrame => {
      print_ssid("ProbeResp", probe_resp.body.ssid());
    }
    probe_req = ProbeRequestFrame => {
      print_ssid("ProbeReq", probe_req.body.ssid());
    }
  };
}

fn print_ssid(kind: &str, ssid: Option<&str>) {
  match ssid {
    Some(name) if !name.is_empty() => println!("  SSID({}): {}", kind, name),
    Some(_) => println!("  SSID({}): <hidden>", kind),
    None => {}
  }
}
