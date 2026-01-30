use std::error::Error;

use tokio::time::{Duration, sleep};
use wifirt::inject::PcapHandle;

const DEFAULT_DEV: &str = "wlx00e04bd3e455";
const DEFAULT_SRC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const BROADCAST: [u8; 6] = [0xff; 6];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let args: Vec<String> = std::env::args().collect();
  let dev = args.get(1).map(String::as_str).unwrap_or(DEFAULT_DEV);

  let handle = PcapHandle::open(dev, 4096, true, 1000)?;
  let mut cnt: u64 = 1;

  loop {
    let payload = format!("Count: {cnt}");
    handle.send_wfirt(DEFAULT_SRC, BROADCAST, DEFAULT_SRC, payload.as_bytes())?;
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
    sleep(Duration::from_millis(100)).await;
  }
}
