use std::{env, path::PathBuf};

pub fn build_with_cmake(target_triple: &str) -> PathBuf {
  let mut cfg = cmake::Config::new("pcap-core");

  cfg.define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON");
  cfg.define("INSTALL_VCPKG_PCAP_STATIC", "ON");

  let toolchain_file = vcpkg_toolchain_file();
  cfg.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);

  if target_triple == "aarch64-unknown-linux-gnu" {
    cfg.define("VCPKG_TARGET_TRIPLET", "arm64-linux");
    println!(
      "cargo:warning=TARGET={} -> set VCPKG_TARGET_TRIPLET=arm64-linux",
      target_triple
    );
  }

  cfg.build()
}

fn vcpkg_toolchain_file() -> PathBuf {
  let vcpkg_root = env::var("VCPKG_ROOT").expect("VCPKG_ROOT is not set");
  PathBuf::from(vcpkg_root)
    .join("scripts")
    .join("buildsystems")
    .join("vcpkg.cmake")
}
