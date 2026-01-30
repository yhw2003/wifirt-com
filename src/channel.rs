use std::time::Duration;

use tokio::{process::Command, time::sleep};

const CHANNEL_LIST: [u16; 25] = [
  36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149,
  153, 157, 161, 165,
];

/// Cycle through the 5GHz channel list, issuing `iw dev <dev> set channel <n>`
/// once per second. Intended for simple background hopping while capturing.
pub async fn hop_channels(dev: &str) {
  let mut idx = 0usize;
  loop {
    if idx >= CHANNEL_LIST.len() {
      idx = 0;
    }
    let channel = CHANNEL_LIST[idx];
    let mut cmd = Command::new("bash");
    let cmd_str = format!("iw dev {dev} set channel {channel}");
    cmd.args(["-c", &cmd_str]);
    println!("Scanning {idx} channel of {}", CHANNEL_LIST.len());
    cmd.spawn().unwrap();
    sleep(Duration::from_secs(1)).await;
    idx += 1;
  }
}
