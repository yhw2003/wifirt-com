use std::path::PathBuf;

use thiserror::Error;

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
