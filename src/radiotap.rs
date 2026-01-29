use nom::{
  bytes::complete::take,
  number::complete::{le_u16, le_u32, u8 as nom_u8},
};
use thiserror::Error;

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

#[derive(Debug, Error)]
pub enum RadiotapError {
  #[error("radiotap header too short: {0} bytes")]
  TruncatedHeader(usize),
  #[error("invalid radiotap version {0}")]
  InvalidVersion(u8),
  #[error("invalid radiotap length {len} (packet {pkt_len})")]
  InvalidLength { len: usize, pkt_len: usize },
  #[error("radiotap parse error: {0}")]
  ParseError(&'static str),
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

pub fn parse_radiotap(pkt: &[u8]) -> Result<(RtMeta, usize), RadiotapError> {
  if pkt.len() < 8 {
    return Err(RadiotapError::TruncatedHeader(pkt.len()));
  }

  let (input, version) = parse_u8(pkt, "version")?;
  if version != 0 {
    return Err(RadiotapError::InvalidVersion(version));
  }
  let (input, _pad) = parse_u8(input, "pad")?;
  let (_, len) = parse_le_u16(input, "length")?;
  let rt_len = len as usize;
  if rt_len < 8 || rt_len > pkt.len() {
    return Err(RadiotapError::InvalidLength {
      len: rt_len,
      pkt_len: pkt.len(),
    });
  }

  let rt_slice = &pkt[..rt_len];
  let mut present_words = Vec::new();
  let (mut rest, mut word) = parse_le_u32(&rt_slice[4..], "present")?;
  present_words.push(word);
  let mut off = 8usize;
  while (word & 0x8000_0000) != 0 {
    if present_words.len() >= 8 {
      break;
    }
    if off + 4 > rt_len {
      break;
    }
    let (next_rest, next_word) = parse_le_u32(rest, "present_ext")?;
    present_words.push(next_word);
    rest = next_rest;
    off += 4;
    word = next_word;
  }

  let meta = parse_fields(rt_slice, off, present_words[0])?;
  Ok((meta, rt_len))
}

fn parse_fields(rt_slice: &[u8], mut cur: usize, present_word0: u32) -> Result<RtMeta, RadiotapError> {
  let mut meta = RtMeta::default();
  let mut input = rt_slice
    .get(cur..)
    .ok_or(RadiotapError::InvalidLength {
      len: rt_slice.len(),
      pkt_len: rt_slice.len(),
    })?;

  for bit in 0..32 {
    if bit == 31 || (present_word0 & (1u32 << bit)) == 0 {
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
      return Ok(meta);
    }

    let aligned = align_up(cur, align);
    if aligned + size > rt_slice.len() {
      return Ok(meta);
    }

    let pad = aligned - cur;
    if pad > 0 {
      input = skip_bytes(input, pad, "padding")?;
      cur = aligned;
    }

    match bit {
      1 => {
        let (rest, flags) = parse_u8(input, "flags")?;
        meta.has_flags = true;
        meta.rt_flags = flags;
        input = rest;
      }
      2 => {
        let (rest, rate) = parse_u8(input, "rate")?;
        meta.has_rate = true;
        meta.rate_500kbps = rate;
        input = rest;
      }
      3 => {
        let (rest, freq) = parse_le_u16(input, "channel_freq")?;
        let (rest, flags) = parse_le_u16(rest, "channel_flags")?;
        meta.has_channel = true;
        meta.chan_freq = freq;
        meta.chan_flags = flags;
        input = rest;
      }
      5 => {
        let (rest, signal) = parse_u8(input, "dbm_signal")?;
        meta.has_dbm_signal = true;
        meta.dbm_signal = signal as i8;
        input = rest;
      }
      11 => {
        let (rest, antenna) = parse_u8(input, "antenna")?;
        meta.has_antenna = true;
        meta.antenna = antenna;
        input = rest;
      }
      _ => {
        input = skip_bytes(input, size, "skip_field")?;
      }
    }

    cur += size;
  }

  Ok(meta)
}

fn parse_u8<'a>(input: &'a [u8], ctx: &'static str) -> Result<(&'a [u8], u8), RadiotapError> {
  nom_u8::<_, nom::error::Error<&[u8]>>(input)
    .map_err(|_| RadiotapError::ParseError(ctx))
}

fn parse_le_u16<'a>(
  input: &'a [u8],
  ctx: &'static str,
) -> Result<(&'a [u8], u16), RadiotapError> {
  le_u16::<_, nom::error::Error<&[u8]>>(input)
    .map_err(|_| RadiotapError::ParseError(ctx))
}

fn parse_le_u32<'a>(
  input: &'a [u8],
  ctx: &'static str,
) -> Result<(&'a [u8], u32), RadiotapError> {
  le_u32::<_, nom::error::Error<&[u8]>>(input)
    .map_err(|_| RadiotapError::ParseError(ctx))
}

fn skip_bytes<'a>(
  input: &'a [u8],
  len: usize,
  ctx: &'static str,
) -> Result<&'a [u8], RadiotapError> {
  take::<_, _, nom::error::Error<&[u8]>>(len)(input)
    .map(|(rest, _)| rest)
    .map_err(|_| RadiotapError::ParseError(ctx))
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse_basic_fields() {
    let present = (1u32 << 1) | (1u32 << 2) | (1u32 << 3) | (1u32 << 5) | (1u32 << 11);
    let mut pkt = Vec::new();
    pkt.push(0);
    pkt.push(0);
    pkt.extend_from_slice(&16u16.to_le_bytes());
    pkt.extend_from_slice(&present.to_le_bytes());
    pkt.push(0x10); // flags
    pkt.push(0x02); // rate
    pkt.extend_from_slice(&2412u16.to_le_bytes()); // channel freq
    pkt.extend_from_slice(&0x00a0u16.to_le_bytes()); // channel flags
    pkt.push(0xd6); // -42 dBm
    pkt.push(1); // antenna

    let (meta, rt_len) = parse_radiotap(&pkt).expect("parse radiotap");
    assert_eq!(rt_len, 16);
    assert!(meta.has_flags);
    assert_eq!(meta.rt_flags, 0x10);
    assert!(meta.has_rate);
    assert_eq!(meta.rate_500kbps, 0x02);
    assert!(meta.has_channel);
    assert_eq!(meta.chan_freq, 2412);
    assert_eq!(meta.chan_flags, 0x00a0);
    assert!(meta.has_dbm_signal);
    assert_eq!(meta.dbm_signal, -42);
    assert!(meta.has_antenna);
    assert_eq!(meta.antenna, 1);
  }

  #[test]
  fn parse_extended_present_header() {
    let present0 = (1u32 << 1) | (1u32 << 31);
    let mut pkt = Vec::new();
    pkt.push(0);
    pkt.push(0);
    pkt.extend_from_slice(&13u16.to_le_bytes());
    pkt.extend_from_slice(&present0.to_le_bytes());
    pkt.extend_from_slice(&0u32.to_le_bytes()); // extended present word
    pkt.push(0x0f); // flags

    let (meta, rt_len) = parse_radiotap(&pkt).expect("parse radiotap");
    assert_eq!(rt_len, 13);
    assert!(meta.has_flags);
    assert_eq!(meta.rt_flags, 0x0f);
  }
}
