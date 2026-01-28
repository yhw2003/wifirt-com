mod capture;
mod channel;
mod decode;
mod radiotap;

#[tokio::main]
async fn main() {
  const DEV: &str = "wlp4s0mon";
  let _capture_task = tokio::spawn(capture::run_capture(DEV, "", decode::handle_packet));
  channel::hop_channels(DEV).await;
}
