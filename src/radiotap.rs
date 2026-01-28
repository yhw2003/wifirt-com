#[derive(Default)]
pub struct RtMeta {
  pub has_rate: bool,
  pub rate_500kbps: u8,

  pub has_channel: bool,
  pub chan_freq: u16,
  pub chan_flags: u16,

  pub has_dbm_signal: bool,
  pub dbm_signal: i8,

  pub has_antenna: bool,
  pub antenna: u8,

  pub has_flags: bool,
  pub rt_flags: u8,
}

fn align_up(off: usize, align: usize) -> usize {
  if align == 0 {
    return off;
  }
  let r = off % align;
  if r == 0 {
    off
  } else {
    off + (align - r)
  }
}

pub fn parse_radiotap(pkt: &[u8]) -> Option<(RtMeta, usize)> {
  if pkt.len() < 8 || pkt[0] != 0 {
    return None;
  }
  let rt_len = u16::from_le_bytes([pkt[2], pkt[3]]) as usize;
  if rt_len < 8 || rt_len > pkt.len() {
    return None;
  }

  let mut present_words = Vec::new();
  let mut p = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
  present_words.push(p);
  let mut off = 8;
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
  let mut cur = off;
  let mut meta = RtMeta::default();

  for (w, word) in present_words.iter().enumerate() {
    for bit in 0..32 {
      if bit == 31 || (word & (1u32 << bit)) == 0 {
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

pub fn freq_to_channel(freq_mhz: u16) -> i32 {
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
