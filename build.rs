use std::{env, fs, path::PathBuf};

fn main() {
  // 让 Cargo 在这些文件变动时重新跑 build.rs（很重要）
  println!("cargo:rerun-if-changed=pcap-core");
  // Cargo 会在构建时提供目标三元组，比如 aarch64-unknown-linux-gnu
  let target = env::var("TARGET").unwrap_or_default();
  let mut dst = cmake::Config::new("pcap-core");
  dst.define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON");
  dst.define("INSTALL_VCPKG_PCAP_STATIC", "ON");
  let vcpkg_root = PathBuf::from(env::var("VCPKG_ROOT").unwrap());
  let toolchain_file = vcpkg_root.join("scripts").join("buildsystems").join("vcpkg.cmake");

  dst.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);
    // 仅当编译 aarch64 linux 目标时，给 CMake 传 vcpkg triplet
  if target == "aarch64-unknown-linux-gnu" {
    dst.define("VCPKG_TARGET_TRIPLET", "arm64-linux");
    // 可选：打印一下，方便你在 cargo build 时确认逻辑生效
    println!("cargo:warning=TARGET={} -> set VCPKG_TARGET_TRIPLET=arm64-linux", target);
  }
  let dst =dst.build();
  let lib_dir = dst.join("lib");
  println!("cargo:rustc-link-search=native={}", lib_dir.display());
  println!("cargo:rustc-link-lib=static=pcap-core");
  println!("cargo:rustc-link-lib=static=pcap");
  let build_dir = dst.join("build");
  let compile_commands = build_dir.join("compile_commands.json");
  if compile_commands.exists() {
    // 项目根目录
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = manifest_dir.join("compile_commands.json");

    // 用拷贝 or 软链接（二选一）
    let _ = fs::remove_file(&target);
    fs::copy(&compile_commands, &target)
        .expect("failed to copy compile_commands.json");
  } else {
      println!("cargo:warning=compile_commands.json不存在")
  } 
}