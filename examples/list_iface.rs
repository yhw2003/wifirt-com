use wifirt::utils::if_helper::list_wireless_ifaces;

#[tokio::main]
async fn main() {
  let iface_list = list_wireless_ifaces().await.unwrap();
  println!("{iface_list:?}");
}
