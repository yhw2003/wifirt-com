use std::{os::raw::c_int, time::Duration};

use tokio::{process::Command, time::sleep};

unsafe extern "C" {
  fn start_demo() -> c_int;
}

#[tokio::main]
async fn main() {
  let hdl = tokio::spawn(run_demo());
  let channel_list = vec![
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
  ];
  let mut cnt = 0;
  loop {
    if cnt >= channel_list.len() {
      cnt = 0;
    }
    let channel_select_cmd_args = vec![
      "-c".to_string(),
      format!(
        "iw dev wlp4s0mon set channel {}",
        channel_list[cnt].to_string()
      ),
    ];
    println!("Scanning {cnt} channel of {}", channel_list.len());
    let mut channel_select_cmd = Command::new("bash");
    channel_select_cmd.args(channel_select_cmd_args);
    channel_select_cmd.spawn().unwrap();
    sleep(Duration::from_secs(1)).await;
    cnt += 1;
  }
}

async fn run_demo() {
  tokio::task::spawn_blocking(move || unsafe {
    start_demo();
  })
  .await
  .unwrap();
}
