use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use tokio::fs;

use super::error::IfHelperError;

#[derive(Debug, PartialEq, Eq)]
pub struct InterfaceHardwareInfo {
  pub driver: Option<String>,
  pub product: Option<String>,
}

pub async fn get_interface_hardware(iface: &str) -> Result<InterfaceHardwareInfo, IfHelperError> {
  get_interface_hardware_from(
    iface,
    Path::new("/sys/class/net"),
    PCI_ID_PATHS,
    USB_ID_PATHS,
  )
  .await
}

pub(crate) async fn get_interface_hardware_from(
  iface: &str,
  net_base: &Path,
  pci_id_paths: &[&str],
  usb_id_paths: &[&str],
) -> Result<InterfaceHardwareInfo, IfHelperError> {
  let dev_path = net_base.join(iface).join("device");

  let driver = fs::read_link(dev_path.join("driver"))
    .await
    .ok()
    .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()));

  // Try PCI first.
  let pci_vendor = read_optional_trimmed(dev_path.join("vendor")).await?;
  let pci_device = read_optional_trimmed(dev_path.join("device")).await?;

  // Then USB.
  let usb_vendor = read_optional_trimmed(dev_path.join("idVendor")).await?;
  let usb_device = read_optional_trimmed(dev_path.join("idProduct")).await?;

  let product = if let (Some(v), Some(d)) = (pci_vendor, pci_device) {
    lookup_device_name(pci_id_paths, &v, &d).await?
  } else if let (Some(v), Some(d)) = (usb_vendor, usb_device) {
    lookup_device_name(usb_id_paths, &v, &d).await?
  } else {
    None
  };

  Ok(InterfaceHardwareInfo { driver, product })
}

async fn lookup_device_name(
  id_paths: &[&str],
  vendor: &str,
  device: &str,
) -> Result<Option<String>, IfHelperError> {
  for path in id_paths {
    match fs::read_to_string(path).await {
      Ok(contents) => {
        if let Some(name) = parse_id_database(&contents, vendor, device) {
          return Ok(Some(name));
        }
      }
      Err(err) if err.kind() == ErrorKind::NotFound => continue,
      Err(err) => {
        return Err(IfHelperError::ReadPath {
          path: PathBuf::from(path),
          source: err,
        });
      }
    }
  }
  Ok(None)
}

fn parse_id_database(contents: &str, vendor: &str, device: &str) -> Option<String> {
  let vendor_lc = normalize_hex(vendor)?;
  let device_lc = normalize_hex(device)?;

  let mut current_vendor: Option<String> = None;

  for line in contents.lines() {
    let trimmed = line.trim_end();
    if trimmed.is_empty() || trimmed.starts_with('#') {
      continue;
    }

    if !trimmed.starts_with('\t') {
      if let Some((id, name)) = split_id_and_name(trimmed) {
        if id.eq_ignore_ascii_case(&vendor_lc) {
          current_vendor = Some(name.to_string());
        } else {
          current_vendor = None;
        }
      }
      continue;
    }

    if let Some(vendor_name) = current_vendor.as_ref() {
      let device_line = trimmed.trim_start_matches('\t');
      if let Some((id, name)) = split_id_and_name(device_line)
        && id.eq_ignore_ascii_case(&device_lc)
      {
        return Some(format!("{vendor_name} {name}"));
      }
    }
  }

  None
}

fn split_id_and_name(line: &str) -> Option<(String, &str)> {
  let mut parts = line.splitn(2, char::is_whitespace);
  let id = parts.next()?.trim().to_string();
  let rest = parts.next()?.trim();
  if id.is_empty() || rest.is_empty() {
    return None;
  }
  Some((id, rest))
}

fn normalize_hex(value: &str) -> Option<String> {
  let trimmed = value.trim();
  let without_prefix = trimmed.trim_start_matches("0x").trim_start_matches("0X");
  if without_prefix.len() < 4 {
    return None;
  }
  Some(without_prefix[..4].to_ascii_lowercase())
}

async fn read_optional_trimmed(path: PathBuf) -> Result<Option<String>, IfHelperError> {
  match fs::read_to_string(&path).await {
    Ok(s) => Ok(Some(s.trim().to_string())),
    Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
    Err(err) => Err(IfHelperError::ReadPath { path, source: err }),
  }
}

const PCI_ID_PATHS: &[&str] = &["/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids"];
const USB_ID_PATHS: &[&str] = &["/usr/share/hwdata/usb.ids", "/usr/share/misc/usb.ids"];

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;
  use std::os::unix::fs::symlink;

  #[tokio::test]
  async fn hardware_info_from_pci_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let net_base = temp.path();
    let device_dir = net_base.join("wlan0/device");
    fs::create_dir_all(&device_dir).expect("mkdir device");
    fs::write(device_dir.join("vendor"), "0x10ec\n").expect("vendor");
    fs::write(device_dir.join("device"), "0xb822\n").expect("device");
    let driver_target = temp.path().join("drivers/rtl88xx");
    fs::create_dir_all(driver_target.parent().unwrap()).expect("mkdir driver parent");
    fs::create_dir_all(&driver_target).expect("mkdir driver");
    symlink(&driver_target, device_dir.join("driver")).expect("symlink driver");

    let ids = temp.path().join("pci.ids");
    fs::write(
      &ids,
      "10ec  Realtek Semiconductor Co., Ltd.\n\tb822 RTL8822BE 802.11a/b/g/n/ac WiFi adapter\n",
    )
    .expect("write ids");

    let info = get_interface_hardware_from("wlan0", net_base, &[ids.to_str().unwrap()], &[])
      .await
      .expect("info");

    assert_eq!(info.driver, Some("rtl88xx".to_string()));
    assert_eq!(
      info.product,
      Some("Realtek Semiconductor Co., Ltd. RTL8822BE 802.11a/b/g/n/ac WiFi adapter".to_string())
    );
  }

  #[tokio::test]
  async fn hardware_info_from_usb_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let net_base = temp.path();
    let device_dir = net_base.join("wlan1/device");
    fs::create_dir_all(&device_dir).expect("mkdir device");
    fs::write(device_dir.join("idVendor"), "0x0bda\n").expect("vendor");
    fs::write(device_dir.join("idProduct"), "0xb812\n").expect("product");
    let driver_target = temp.path().join("drivers/rtlusb");
    fs::create_dir_all(driver_target.parent().unwrap()).expect("mkdir driver parent");
    fs::create_dir_all(&driver_target).expect("mkdir driver");
    symlink(&driver_target, device_dir.join("driver")).expect("symlink driver");

    let ids = temp.path().join("usb.ids");
    fs::write(
      &ids,
      "0bda  Realtek Semiconductor Corp.\n\tb812 RTL8812AU 802.11a/b/g/n/ac WLAN Adapter\n",
    )
    .expect("write ids");

    let info = get_interface_hardware_from("wlan1", net_base, &[], &[ids.to_str().unwrap()])
      .await
      .expect("info");

    assert_eq!(info.driver, Some("rtlusb".to_string()));
    assert_eq!(
      info.product,
      Some("Realtek Semiconductor Corp. RTL8812AU 802.11a/b/g/n/ac WLAN Adapter".to_string())
    );
  }
}
