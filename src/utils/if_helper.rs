use std::{
  io::ErrorKind,
  path::{Path, PathBuf},
};

use thiserror::Error;
use tokio::{fs, process::Command};

#[derive(Debug, Error)]
pub enum IfHelperError {
  #[error("failed to spawn {program}: {source}")]
  Spawn {
    program: &'static str,
    #[source]
    source: std::io::Error,
  },

  #[error("{program} returned non-zero status {status:?}: {stderr}")]
  CommandFailed {
    program: &'static str,
    status: Option<i32>,
    stderr: String,
  },

  #[error("failed to read {path}: {source}")]
  ReadPath {
    path: PathBuf,
    #[source]
    source: std::io::Error,
  },
}

#[derive(Debug, PartialEq, Eq)]
pub struct InterfaceHardwareInfo {
  pub driver: Option<String>,
  pub product: Option<String>,
}

/// Shut down a wireless interface: `ip link set <iface> down`.
pub async fn bring_interface_down(iface: &str) -> Result<(), IfHelperError> {
  run_command("ip", &["link", "set", iface, "down"]).await
}

/// Set an interface to monitor mode: `iw dev <iface> set type monitor`.
pub async fn set_monitor_mode(iface: &str) -> Result<(), IfHelperError> {
  run_command("iw", &["dev", iface, "set", "type", "monitor"]).await
}

/// Bring an interface back up: `ip link set <iface> up`.
pub async fn bring_interface_up(iface: &str) -> Result<(), IfHelperError> {
  run_command("ip", &["link", "set", iface, "up"]).await
}

/// Set transmit power in dBm: `iwconfig <iface> txpower <dbm>`.
pub async fn set_tx_power_dbm(iface: &str, dbm: i16) -> Result<(), IfHelperError> {
  run_command("iwconfig", &[iface, "txpower", &dbm.to_string()]).await
}

/// List wireless interface names by inspecting `/sys/class/net/<iface>/wireless`.
pub async fn list_wireless_ifaces() -> Result<Vec<String>, IfHelperError> {
  list_wireless_ifaces_from(Path::new("/sys/class/net")).await
}

/// Query driver name and human-readable product name for an interface.
pub async fn get_interface_hardware(iface: &str) -> Result<InterfaceHardwareInfo, IfHelperError> {
  get_interface_hardware_from(
    iface,
    Path::new("/sys/class/net"),
    PCI_ID_PATHS,
    USB_ID_PATHS,
  )
  .await
}

/// Desired interface state check result.
#[derive(Debug, PartialEq, Eq)]
pub enum InterfaceStatus {
  Correct,
  Incorrect,
  Unknown,
}

/// Verify interface is `up` and in monitor mode.
pub async fn check_iface_monitor_up(iface: &str) -> Result<InterfaceStatus, IfHelperError> {
  check_iface_monitor_up_from(iface, Path::new("/sys/class/net")).await
}

async fn run_command(program: &'static str, args: &[&str]) -> Result<(), IfHelperError> {
  let output = Command::new(resolve_program(program))
    .args(args)
    .output()
    .await
    .map_err(|source| IfHelperError::Spawn { program, source })?;

  if output.status.success() {
    return Ok(());
  }

  let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
  Err(IfHelperError::CommandFailed {
    program,
    status: output.status.code(),
    stderr,
  })
}

/// Resolve binary path; tests can override via `IF_HELPER_BIN_DIR`.
fn resolve_program(program: &'static str) -> PathBuf {
  std::env::var_os("IF_HELPER_BIN_DIR")
    .map(PathBuf::from)
    .map(|dir| dir.join(program))
    .unwrap_or_else(|| PathBuf::from(program))
}

async fn list_wireless_ifaces_from(base: &Path) -> Result<Vec<String>, IfHelperError> {
  let mut entries = fs::read_dir(base)
    .await
    .map_err(|source| IfHelperError::ReadPath {
      path: base.to_path_buf(),
      source,
    })?;

  let mut names = Vec::new();
  while let Some(entry) = entries
    .next_entry()
    .await
    .map_err(|source| IfHelperError::ReadPath {
      path: base.to_path_buf(),
      source,
    })?
  {
    let name = entry.file_name();
    let iface_path = entry.path();
    let wireless_path = iface_path.join("wireless");
    if fs::metadata(&wireless_path).await.is_ok() {
      names.push(name.to_string_lossy().to_string());
    }
  }

  Ok(names)
}

async fn get_interface_hardware_from(
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

async fn check_iface_monitor_up_from(
  iface: &str,
  net_base: &Path,
) -> Result<InterfaceStatus, IfHelperError> {
  let oper_path = net_base.join(iface).join("operstate");
  let operstate =
    fs::read_to_string(&oper_path)
      .await
      .map_err(|source| IfHelperError::ReadPath {
        path: oper_path.clone(),
        source,
      })?;
  let is_up = operstate.trim() == "up";

  let iw_info = read_iw_info(iface).await?;
  let iface_type = parse_iw_type(&iw_info);

  match iface_type {
    None => Ok(InterfaceStatus::Unknown),
    Some(t) if t == "monitor" && is_up => Ok(InterfaceStatus::Correct),
    Some(_) => Ok(InterfaceStatus::Incorrect),
  }
}

async fn read_iw_info(iface: &str) -> Result<String, IfHelperError> {
  let output = Command::new(resolve_program("iw"))
    .args(["dev", iface, "info"])
    .output()
    .await
    .map_err(|source| IfHelperError::Spawn {
      program: "iw",
      source,
    })?;

  if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    return Err(IfHelperError::CommandFailed {
      program: "iw",
      status: output.status.code(),
      stderr,
    });
  }

  Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_iw_type(info: &str) -> Option<String> {
  info
    .lines()
    .find_map(|line| line.trim().strip_prefix("type "))
    .map(|s| s.trim().to_string())
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
  use std::sync::Mutex;
  use std::{fs, os::unix::fs::PermissionsExt, path::Path};

  static SERIAL_TEST: Mutex<()> = Mutex::new(());

  struct EnvGuard {
    key: &'static str,
    original: Option<std::ffi::OsString>,
  }

  impl EnvGuard {
    fn set_path(key: &'static str, path: &Path) -> Self {
      let original = std::env::var_os(key);
      // set_var/remove_var are unsafe on Rust 1.93 because env is global.
      unsafe { std::env::set_var(key, path) };
      Self { key, original }
    }
  }

  impl Drop for EnvGuard {
    fn drop(&mut self) {
      if let Some(val) = self.original.take() {
        unsafe { std::env::set_var(self.key, val) };
      } else {
        unsafe { std::env::remove_var(self.key) };
      }
    }
  }

  fn write_stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write stub");
    let mut perms = fs::metadata(&path).expect("stat stub").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod stub");
  }

  #[tokio::test]
  async fn commands_succeed_with_stubbed_bins() {
    let _serial = SERIAL_TEST.lock().expect("serial lock");
    let temp = tempfile::tempdir().expect("tempdir");
    write_stub(temp.path(), "ip", "exit 0");
    write_stub(temp.path(), "iw", "exit 0");
    write_stub(temp.path(), "iwconfig", "exit 0");
    let _guard = EnvGuard::set_path("IF_HELPER_BIN_DIR", temp.path());
    assert_eq!(resolve_program("ip"), temp.path().join("ip"));

    bring_interface_down("wlan0").await.expect("ip down");
    set_monitor_mode("wlan0").await.expect("iw monitor");
    bring_interface_up("wlan0").await.expect("ip up");
    set_tx_power_dbm("wlan0", 20).await.expect("tx power");
  }

  #[tokio::test]
  async fn propagates_non_zero_status() {
    let _serial = SERIAL_TEST.lock().expect("serial lock");
    let temp = tempfile::tempdir().expect("tempdir");
    write_stub(temp.path(), "ip", "echo fail >&2\nexit 7");
    let _guard = EnvGuard::set_path("IF_HELPER_BIN_DIR", temp.path());

    let err = bring_interface_down("wlan0")
      .await
      .expect_err("ip should fail");
    match err {
      IfHelperError::CommandFailed {
        program,
        status,
        stderr,
      } => {
        assert_eq!(program, "ip");
        assert_eq!(status, Some(7));
        assert!(stderr.contains("fail"));
      }
      other => panic!("unexpected error: {other:?}"),
    }
  }

  #[tokio::test]
  async fn list_wireless_from_sysfs_tree() {
    let temp = tempfile::tempdir().expect("tempdir");
    // wlan0 is wireless
    fs::create_dir_all(temp.path().join("wlan0/wireless")).expect("mkdir wlan0");
    // eth0 is not
    fs::create_dir_all(temp.path().join("eth0")).expect("mkdir eth0");
    // wlp2s0 is wireless
    fs::create_dir_all(temp.path().join("wlp2s0/wireless")).expect("mkdir wlp2s0");

    let mut ifaces = list_wireless_ifaces_from(temp.path()).await.expect("list");
    ifaces.sort();
    assert_eq!(ifaces, vec!["wlan0", "wlp2s0"]);
  }

  fn write_operstate(base: &Path, iface: &str, state: &str) {
    let path = base.join(iface);
    fs::create_dir_all(&path).expect("mkdir iface");
    fs::write(path.join("operstate"), format!("{state}\n")).expect("write operstate");
  }

  fn iw_info_script(body: &str) -> String {
    format!("#!/bin/sh\ncat <<'EOF'\n{body}\nEOF\nexit 0\n")
  }

  #[tokio::test]
  async fn status_correct_when_up_and_monitor() {
    let _serial = SERIAL_TEST.lock().expect("serial lock");
    let temp = tempfile::tempdir().expect("tempdir");
    write_operstate(temp.path(), "wlan0", "up");
    write_stub(
      temp.path(),
      "iw",
      &iw_info_script("Interface wlan0\n\ttype monitor\n\tssid test\n"),
    );
    let _guard = EnvGuard::set_path("IF_HELPER_BIN_DIR", temp.path());

    let status = check_iface_monitor_up_from("wlan0", temp.path())
      .await
      .expect("status");
    assert_eq!(status, InterfaceStatus::Correct);
  }

  #[tokio::test]
  async fn status_incorrect_when_not_monitor() {
    let _serial = SERIAL_TEST.lock().expect("serial lock");
    let temp = tempfile::tempdir().expect("tempdir");
    write_operstate(temp.path(), "wlan1", "up");
    write_stub(
      temp.path(),
      "iw",
      &iw_info_script("Interface wlan1\n\ttype managed\n"),
    );
    let _guard = EnvGuard::set_path("IF_HELPER_BIN_DIR", temp.path());

    let status = check_iface_monitor_up_from("wlan1", temp.path())
      .await
      .expect("status");
    assert_eq!(status, InterfaceStatus::Incorrect);
  }

  #[tokio::test]
  async fn status_unknown_when_type_missing() {
    let _serial = SERIAL_TEST.lock().expect("serial lock");
    let temp = tempfile::tempdir().expect("tempdir");
    write_operstate(temp.path(), "wlan2", "up");
    write_stub(
      temp.path(),
      "iw",
      &iw_info_script("Interface wlan2\n\tssid test\n"),
    );
    let _guard = EnvGuard::set_path("IF_HELPER_BIN_DIR", temp.path());

    let status = check_iface_monitor_up_from("wlan2", temp.path())
      .await
      .expect("status");
    assert_eq!(status, InterfaceStatus::Unknown);
  }

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
    // create dummy driver directory to link to
    fs::create_dir_all(&driver_target).expect("mkdir driver");
    std::os::unix::fs::symlink(&driver_target, device_dir.join("driver")).expect("symlink driver");

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
    std::os::unix::fs::symlink(&driver_target, device_dir.join("driver")).expect("symlink driver");

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
