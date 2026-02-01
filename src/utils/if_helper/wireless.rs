use std::path::Path;

use tokio::{fs, process::Command};

use super::common::resolve_program;
use super::error::IfHelperError;

/// Desired interface state check result.
#[derive(Debug, PartialEq, Eq)]
pub enum InterfaceStatus {
  Correct,
  Incorrect,
  Unknown,
}

/// List wireless interface names by inspecting `/sys/class/net/<iface>/wireless`.
pub async fn list_wireless_ifaces() -> Result<Vec<String>, IfHelperError> {
  list_wireless_ifaces_from(Path::new("/sys/class/net")).await
}

/// Verify interface is `up` and in monitor mode.
pub async fn check_iface_monitor_up(iface: &str) -> Result<InterfaceStatus, IfHelperError> {
  check_iface_monitor_up_from(iface, Path::new("/sys/class/net")).await
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

#[cfg(test)]
mod tests {
  use super::*;
  use std::os::unix::fs::PermissionsExt;
  use std::{fs, path::Path};

  struct EnvGuard {
    key: &'static str,
    original: Option<std::ffi::OsString>,
  }

  impl EnvGuard {
    fn set_path(key: &'static str, path: &Path) -> Self {
      let original = std::env::var_os(key);
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

  fn write_operstate(base: &Path, iface: &str, state: &str) {
    let path = base.join(iface);
    fs::create_dir_all(&path).expect("mkdir iface");
    fs::write(path.join("operstate"), format!("{state}\n")).expect("write operstate");
  }

  fn iw_info_script(body: &str) -> String {
    format!("#!/bin/sh\ncat <<'EOF'\n{body}\nEOF\nexit 0\n")
  }

  fn write_stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, iw_info_script(body)).expect("write stub");
    let mut perms = fs::metadata(&path).expect("stat stub").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod stub");
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

  #[tokio::test]
  async fn status_correct_when_up_and_monitor() {
    let _serial = crate::utils::if_helper::common::ENV_LOCK
      .lock()
      .expect("serial lock");
    let temp = tempfile::tempdir().expect("tempdir");
    write_operstate(temp.path(), "wlan0", "up");
    write_stub(
      temp.path(),
      "iw",
      "Interface wlan0\n\ttype monitor\n\tssid test\n",
    );
    let _guard = EnvGuard::set_path("IF_HELPER_BIN_DIR", temp.path());

    let status = check_iface_monitor_up_from("wlan0", temp.path())
      .await
      .expect("status");
    assert_eq!(status, InterfaceStatus::Correct);
  }

  #[tokio::test]
  async fn status_incorrect_when_not_monitor() {
    let _serial = crate::utils::if_helper::common::ENV_LOCK
      .lock()
      .expect("serial lock");
    let temp = tempfile::tempdir().expect("tempdir");
    write_operstate(temp.path(), "wlan1", "up");
    write_stub(temp.path(), "iw", "Interface wlan1\n\ttype managed\n");
    let _guard = EnvGuard::set_path("IF_HELPER_BIN_DIR", temp.path());

    let status = check_iface_monitor_up_from("wlan1", temp.path())
      .await
      .expect("status");
    assert_eq!(status, InterfaceStatus::Incorrect);
  }

  #[tokio::test]
  async fn status_unknown_when_type_missing() {
    let _serial = crate::utils::if_helper::common::ENV_LOCK
      .lock()
      .expect("serial lock");
    let temp = tempfile::tempdir().expect("tempdir");
    write_operstate(temp.path(), "wlan2", "up");
    write_stub(temp.path(), "iw", "Interface wlan2\n\tssid test\n");
    let _guard = EnvGuard::set_path("IF_HELPER_BIN_DIR", temp.path());

    let status = check_iface_monitor_up_from("wlan2", temp.path())
      .await
      .expect("status");
    assert_eq!(status, InterfaceStatus::Unknown);
  }
}
