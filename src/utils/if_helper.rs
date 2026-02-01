use std::path::{Path, PathBuf};

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
}
