//! WFRT framing helpers (encode/decode) and related constants.

use thiserror::Error;

pub const WFRT_MAGIC: [u8; 4] = *b"WFRT";
pub const WFRT_HEADER_LEN: usize = 6;

#[derive(Debug, Error)]
pub enum ProtocolError {
  #[error("WFRT payload too long: {len} bytes (max 65535)")]
  PayloadTooLong { len: usize },
}

/// Prefix payload with WFRT magic + length.
pub fn encode_wfirt_payload(payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
  if payload.len() > u16::MAX as usize {
    return Err(ProtocolError::PayloadTooLong { len: payload.len() });
  }

  let mut buf = Vec::with_capacity(WFRT_HEADER_LEN + payload.len());
  buf.extend_from_slice(&WFRT_MAGIC);
  buf.extend_from_slice(&(payload.len() as u16).to_le_bytes());
  buf.extend_from_slice(payload);
  Ok(buf)
}

/// Validate WFRT header and return the payload slice if length matches.
pub fn decode_wfirt_payload(bytes: &[u8]) -> Option<&[u8]> {
  if bytes.len() < WFRT_HEADER_LEN {
    return None;
  }
  if bytes.get(..WFRT_MAGIC.len())? != WFRT_MAGIC {
    return None;
  }

  let len = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
  let start = WFRT_HEADER_LEN;
  let end = start.checked_add(len)?;
  bytes.get(start..end)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn encode_and_decode_roundtrip() {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let framed = encode_wfirt_payload(&payload).expect("encode");
    assert_eq!(&framed[..4], WFRT_MAGIC);
    let decoded = decode_wfirt_payload(&framed).expect("decode");
    assert_eq!(decoded, payload);
  }

  #[test]
  fn reject_too_short() {
    assert!(decode_wfirt_payload(&[0u8; 3]).is_none());
  }

  #[test]
  fn reject_excess_len() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&WFRT_MAGIC);
    bytes.extend_from_slice(&10u16.to_le_bytes());
    bytes.extend_from_slice(&[0x01, 0x02, 0x03]);
    assert!(decode_wfirt_payload(&bytes).is_none());
  }
}
