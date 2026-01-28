use std::{
  ffi::CString,
  os::raw::{c_char, c_int, c_void},
};

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

pub async fn run_capture(dev: &str, filter: &str) {
  let dev = dev.to_string();
  let filter = filter.to_string();
  tokio::task::spawn_blocking(move || unsafe {
    let dev_c = CString::new(dev).expect("device has nul");
    let filter_c = CString::new(filter).expect("filter has nul");
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
    crate::decode::handle_packet(bytes, caplen, len, ts_sec, ts_usec);
  });
}
