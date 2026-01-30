use wifirt::{decode, inject::PcapHandle};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  const DEV: &str = "wlp4s0mon";
  let mut handle = PcapHandle::open(DEV, 4096, true, 1000)?;
  handle.set_filter("")?;
  // channel::hop_channels(DEV).await;
  handle.capture_async(decode::handle_packet).await?;
  Ok(())
}
