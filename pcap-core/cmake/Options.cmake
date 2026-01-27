# =========================
# Options.cmake
# - 放置全局构建选项/默认值
# =========================

# C 标准：你原来是 set(CMAKE_C_STANDARD 17)
# 说明：更现代的写法是对 target 用 target_compile_features，
# 但这里保持与你原本一致，且更直观。
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# 可选：导出 compile_commands.json（便于 clangd/IDE）
option(CMAKE_EXPORT_COMPILE_COMMANDS "Export compile commands" ON)
