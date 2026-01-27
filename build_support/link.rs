use std::path::PathBuf;

pub fn emit_link_flags(dst: &PathBuf) {
  let lib_dir = dst.join("lib");
  println!("cargo:rustc-link-search=native={}", lib_dir.display());
  println!("cargo:rustc-link-lib=static=pcap-core");
  println!("cargo:rustc-link-lib=static=pcap");
}
