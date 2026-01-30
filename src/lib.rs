//! Wi-Fi Radiotap (WFRT) toolkit: capture, decode and inject 802.11 frames.
//!
//! Modules are organized by responsibility:
//! - `pcap`: safe wrapper around the C libpcap helpers, plus injection helpers.
//! - `capture`: parsing of radiotap + 802.11 headers and capture loop helpers.
//! - `decode`: human-friendly printing / sample handler for captured packets.
//! - `protocol`: WFRT framing helpers.
//! - `radiotap`: minimal radiotap parser.
//! - `channel`: channel hopping utility.
//! - `ffi`: raw FFI boundary to `pcap-core` (unsafe, not re-exported publicly).

pub mod capture;
pub mod channel;
pub mod decode;
pub mod ffi;
pub mod pcap;
pub mod protocol;
pub mod radiotap;
