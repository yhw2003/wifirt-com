use std::path::PathBuf;

#[cfg(test)]
pub(crate) static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) fn resolve_program(program: &'static str) -> PathBuf {
  std::env::var_os("IF_HELPER_BIN_DIR")
    .map(PathBuf::from)
    .map(|dir| dir.join(program))
    .unwrap_or_else(|| PathBuf::from(program))
}
