use wifirt::utils::if_helper::{
  hardware::get_interface_hardware,
  wireless::{check_iface_monitor_up, list_wireless_ifaces},
};

#[tokio::main]
async fn main() {
  let iface_list = list_wireless_ifaces().await.unwrap();
  for iface in iface_list {
    let state = check_iface_monitor_up(&iface).await;
    let hi = get_interface_hardware(&iface).await;
    println!("=>找到WIFI网卡: {iface}， 状态： {state:?} {hi:?}");
  }
}
