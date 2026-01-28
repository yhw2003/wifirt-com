use std::{
  ffi::CString,
  os::raw::{c_char, c_int, c_void},
  time::Duration,
};

use tokio::{process::Command, time::sleep};

type PacketCallback = unsafe extern "C" fn(*const u8, u32, u32, u64, u32, *mut c_void);

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

#[tokio::main]
async fn main() {
  const DEV: &str = "wlp4s0mon";
  let _hdl = tokio::spawn(run_capture(DEV));
  let channel_list = vec![
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
  ];
  let mut cnt = 0;
  loop {
    if cnt >= channel_list.len() {
      cnt = 0;
    }
    let channel_select_cmd_args = vec![
      "-c".to_string(),
      format!("iw dev {DEV} set channel {}", channel_list[cnt].to_string()),
    ];
    println!("Scanning {cnt} channel of {}", channel_list.len());
    let mut channel_select_cmd = Command::new("bash");
    channel_select_cmd.args(channel_select_cmd_args);
    channel_select_cmd.spawn().unwrap();
    sleep(Duration::from_secs(1)).await;
    cnt += 1;
  }
}

async fn run_capture(dev: &str) {
  let dev = dev.to_string();
  tokio::task::spawn_blocking(move || unsafe {
    let dev_c = CString::new(dev).expect("device has nul");
    let filter_c = CString::new("").expect("filter has nul");
    let ret = pcap_start_capture(
      dev_c.as_ptr(),
      filter_c.as_ptr(),
      4096,
      1,
      1000,
      on_packet,
      std::ptr::null_mut(),
    );
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
  _user: *mut c_void,
) {
  if data.is_null() || caplen == 0 {
    return;
  }
  let bytes = unsafe { std::slice::from_raw_parts(data, caplen as usize) };
  let _ = std::panic::catch_unwind(|| {
    handle_packet(bytes, caplen, len, ts_sec, ts_usec);
  });
}

#[derive(Default)]
struct RtMeta {
  has_rate: bool,
  rate_500kbps: u8,

  has_channel: bool,
  chan_freq: u16,
  chan_flags: u16,

  has_dbm_signal: bool,
  dbm_signal: i8,

  has_antenna: bool,
  antenna: u8,

  has_flags: bool,
  rt_flags: u8,
}

fn align_up(off: usize, align: usize) -> usize {
  if align == 0 {
    return off;
  }
  let r = off % align;
  if r == 0 { off } else { off + (align - r) }
}

fn parse_radiotap(pkt: &[u8]) -> Option<(RtMeta, usize)> {
  if pkt.len() < 8 {
    return None;
  }
  if pkt[0] != 0 {
    return None;
  }
  let rt_len = u16::from_le_bytes([pkt[2], pkt[3]]) as usize;
  if rt_len < 8 || rt_len > pkt.len() {
    return None;
  }

  let mut present_words = Vec::new();
  let mut off = 4;
  let mut p = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
  present_words.push(p);
  off = 8;
  while (p & 0x8000_0000) != 0 {
    if present_words.len() >= 8 {
      break;
    }
    if off + 4 > rt_len {
      break;
    }
    p = u32::from_le_bytes([pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]]);
    present_words.push(p);
    off += 4;
  }
  let fields_off = off;
  let mut cur = fields_off;

  let mut meta = RtMeta::default();

  for (w, word) in present_words.iter().enumerate() {
    for bit in 0..32 {
      if bit == 31 {
        continue;
      }
      if (word & (1u32 << bit)) == 0 {
        continue;
      }

      let (size, align) = match bit {
        0 => (8usize, 8usize),
        1 => (1, 1),
        2 => (1, 1),
        3 => (4, 2),
        4 => (2, 2),
        5 => (1, 1),
        6 => (1, 1),
        7 => (2, 2),
        8 => (2, 2),
        9 => (2, 2),
        10 => (1, 1),
        11 => (1, 1),
        12 => (1, 1),
        13 => (1, 1),
        14 => (2, 2),
        15 => (2, 2),
        16 => (1, 1),
        17 => (1, 1),
        _ => (0, 0),
      };

      if size == 0 {
        return Some((meta, rt_len));
      }

      cur = align_up(cur, align);
      if cur + size > rt_len {
        return Some((meta, rt_len));
      }

      let fp = &pkt[cur..cur + size];

      if w == 0 {
        match bit {
          1 => {
            meta.has_flags = true;
            meta.rt_flags = fp[0];
          }
          2 => {
            meta.has_rate = true;
            meta.rate_500kbps = fp[0];
          }
          3 => {
            meta.has_channel = true;
            meta.chan_freq = u16::from_le_bytes([fp[0], fp[1]]);
            meta.chan_flags = u16::from_le_bytes([fp[2], fp[3]]);
          }
          5 => {
            meta.has_dbm_signal = true;
            meta.dbm_signal = fp[0] as i8;
          }
          11 => {
            meta.has_antenna = true;
            meta.antenna = fp[0];
          }
          _ => {}
        }
      }

      cur += size;
    }
  }

  Some((meta, rt_len))
}

fn freq_to_channel(freq_mhz: u16) -> i32 {
  if (2412..=2472).contains(&freq_mhz) {
    return ((freq_mhz as i32) - 2407) / 5;
  }
  if freq_mhz == 2484 {
    return 14;
  }
  if (5000..=5900).contains(&freq_mhz) {
    return ((freq_mhz as i32) - 5000) / 5;
  }
  -1
}

fn type_str(t: u8) -> &'static str {
  match t {
    0 => "MGMT",
    1 => "CTRL",
    2 => "DATA",
    _ => "RSVD",
  }
}

fn mgmt_subtype_str(st: u8) -> &'static str {
  match st {
    0 => "AssocReq",
    1 => "AssocResp",
    2 => "ReassocReq",
    3 => "ReassocResp",
    4 => "ProbeReq",
    5 => "ProbeResp",
    8 => "Beacon",
    10 => "Disassoc",
    11 => "Auth",
    12 => "Deauth",
    13 => "Action",
    _ => "MgmtOther",
  }
}

fn mac_to_str(m: &[u8; 6]) -> String {
  format!(
    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
    m[0], m[1], m[2], m[3], m[4], m[5]
  )
}

fn print_ssid_if_any(p80211: &[u8], type_: u8, subtype: u8) {
  if type_ != 0 || !(subtype == 8 || subtype == 5) {
    return;
  }
  if p80211.len() < 24 + 12 {
    return;
  }
  let ies = &p80211[24 + 12..];
  let mut off = 0usize;
  while off + 2 <= ies.len() {
    let id = ies[off];
    let len = ies[off + 1] as usize;
    off += 2;
    if off + len > ies.len() {
      return;
    }
    if id == 0 {
      print!("  SSID: ");
      if len == 0 {
        println!("<hidden>");
      } else {
        let end = len.min(32);
        let mut s = String::with_capacity(end);
        for &c in &ies[off..off + end] {
          if (32..=126).contains(&c) {
            s.push(c as char);
          } else {
            s.push('.');
          }
        }
        println!("{s}");
      }
      return;
    }
    off += len;
  }
}

fn handle_packet(bytes: &[u8], caplen: u32, len: u32, ts_sec: u64, ts_usec: u32) {
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
  if p80211.len() < 24 {
    return;
  }

  let fc = u16::from_le_bytes([p80211[0], p80211[1]]);
  let duration = u16::from_le_bytes([p80211[2], p80211[3]]);
  let addr1: [u8; 6] = p80211[4..10].try_into().unwrap();
  let addr2: [u8; 6] = p80211[10..16].try_into().unwrap();
  let addr3: [u8; 6] = p80211[16..22].try_into().unwrap();
  let seq_ctrl = u16::from_le_bytes([p80211[22], p80211[23]]);

  let type_ = ((fc >> 2) & 0x3) as u8;
  let subtype = ((fc >> 4) & 0xF) as u8;

  let to_ds = (fc >> 8) & 0x1;
  let from_ds = (fc >> 9) & 0x1;
  let retry = (fc >> 11) & 0x1;
  let pwrmgmt = (fc >> 12) & 0x1;
  let moredata = (fc >> 13) & 0x1;
  let protect = (fc >> 14) & 0x1;

  let a1 = mac_to_str(&addr1);
  let a2 = mac_to_str(&addr2);
  let a3 = mac_to_str(&addr3);

  let frag = seq_ctrl & 0xF;
  let seqno = (seq_ctrl >> 4) & 0xFFF;

  print!(
    "802.11: type={}({}) subtype={}",
    type_str(type_),
    type_,
    subtype
  );
  if type_ == 0 {
    print!("({})", mgmt_subtype_str(subtype));
  }
  println!(
    " ToDS={} FromDS={} Retry={} Protected={} PwrMgmt={} MoreData={}",
    to_ds, from_ds, retry, protect, pwrmgmt, moredata
  );

  println!("ADDR: RA/DA={} TA/SA={} BSSID/3={}", a1, a2, a3);
  println!("SEQ: seq={} frag={} duration={}", seqno, frag, duration);

  print_ssid_if_any(p80211, type_, subtype);

  println!();
}
