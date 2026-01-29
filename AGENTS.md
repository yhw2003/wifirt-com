# AGENTS

## Project Overview
- What this project does: 通过wifi网卡的monitor模式和frame inject实现wifi广播通信。
- Key directories:
  - src/: Rust源码
  - pcap-core/: C语言libpcap封装
  - kernel-ext/: 内核模块和ebpf
  - drivers/: 部分网卡使用frame inject需要对魔改驱动


## Quality Rules
- Prefer idiomatic Rust.
- Avoid `unwrap()`/`expect()` in library code unless justified; in tests it's acceptable.
- Handle errors via `Result` and meaningful error messages.
- Keep clippy clean; do not add `#[allow(clippy::...)]` unless there's a strong reason and comment why.
- 使用thiserror定义自己的错误类，不要让第三方库的Result类型在代码里传递。


## Goal
When making code changes, always add or update necessary tests, and verify the change by running:
- cargo check
- cargo test
- cargo clippy