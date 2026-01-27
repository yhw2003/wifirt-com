pub mod cmake_build;
pub mod compile_commands;
pub mod link;

pub fn run() {
  // 触发条件
  println!("cargo:rerun-if-changed=pcap-core");

  let target_triple = std::env::var("TARGET").unwrap_or_default();

  let dst = cmake_build::build_with_cmake(&target_triple);
  link::emit_link_flags(&dst);
  compile_commands::export_compile_commands(&dst);
}
