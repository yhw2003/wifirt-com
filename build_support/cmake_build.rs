use std::path::PathBuf;

pub fn build_with_cmake(target_triple: &str) -> PathBuf {
  let mut cfg = cmake::Config::new("pcap-core");

  cfg.define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON");
  cfg.define("INSTALL_VCPKG_PCAP_STATIC", "ON");

  if target_triple == "aarch64-unknown-linux-gnu" {
    cfg.define("VCPKG_TARGET_TRIPLET", "arm64-linux");
    println!(
      "cargo:warning=TARGET={} -> set VCPKG_TARGET_TRIPLET=arm64-linux",
      target_triple
    );
  }

  cfg.build()
}
