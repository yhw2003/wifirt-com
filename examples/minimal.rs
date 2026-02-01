use std::time::Duration;

use wifirt::{decode, pcap::PcapHandle, utils};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  const DEV: &str = "wlp199s0f3u1";
  let mut handle = PcapHandle::open(DEV, 4096, true, 1000)?;
  handle.set_filter("")?;
  let cap_hdl = handle.capture_async(decode::handle_packet);
  let hop_hdl = utils::channel::hop_channels(DEV, None, Duration::from_secs(1));
  tokio::select! {
    c = cap_hdl => {
      c.unwrap();
    },
    h = hop_hdl => {
      h.unwrap();
    }
  }
  Ok(())
}
