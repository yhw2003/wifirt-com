//! Raw FFI bindings that talk directly to the C `pcap-core` layer.
//!
//! All `unsafe extern` declarations are centralized here to contain the
//! surface area where we cross the FFI boundary. Higher-level modules should
//! use the safe wrappers in `crate::pcap` instead of calling these functions
//! directly.

use std::os::raw::{c_char, c_int};

/// Opaque marker type for the underlying `pcap_t` handle allocated in C.
#[repr(C)]
pub struct PcapHandleRaw {
  _private: [u8; 0],
}

/// Lightweight view returned from C for a captured packet.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PcapPacketView {
  pub data: *const u8,
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
