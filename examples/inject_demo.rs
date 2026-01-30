use std::{error::Error, sync::Arc, time::Duration};

use tokio::time::sleep;
use wifirt::inject;

const DEFAULT_DEV: &str = "wlp199s0f3u1";
const DEFAULT_SRC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let mut cnt = 1;
  loop {
    let args: Vec<String> = std::env::args().collect();
    let dev = args.get(1).map(String::as_str).unwrap_or(DEFAULT_DEV);
    // let payload = args
    //   .get(2)
    //   .map(|s| s.as_bytes().to_vec())
    //   .unwrap_or_else(|| b"hello from wifirt".to_vec());
    let payload = format!("Count: {cnt}");
    let payload = payload.as_bytes();

    inject::send_wfirt_broadcast(dev, DEFAULT_SRC, &payload)?;
    println!(
      "Injected WFRT payload ({} bytes) via {} from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
      payload.len(),
      dev,
      DEFAULT_SRC[0],
      DEFAULT_SRC[1],
      DEFAULT_SRC[2],
      DEFAULT_SRC[3],
      DEFAULT_SRC[4],
      DEFAULT_SRC[5]
    );
    cnt += 1;
    Arc::new(sleep(Duration::from_secs_f32(0.5f32)).await);
  }
}
