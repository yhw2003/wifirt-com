use std::{
  env, fs,
  path::{Path, PathBuf},
};

pub fn export_compile_commands(dst: &Path) {
  let build_dir = dst.join("build");
  let compile_commands = build_dir.join("compile_commands.json");

  if !compile_commands.exists() {
    println!("cargo:warning=compile_commands.json 不存在");
    return;
  }

  let manifest_dir =
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
  let target_path = manifest_dir.join("compile_commands.json");

  let _ = fs::remove_file(&target_path);
  fs::copy(&compile_commands, &target_path).expect("failed to copy compile_commands.json");
}
