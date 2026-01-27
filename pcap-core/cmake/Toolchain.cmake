# =========================
# Toolchain.cmake
# - vcpkg / toolchain 相关逻辑
# =========================
# ⚠️ 注意：
# CMAKE_TOOLCHAIN_FILE 通常需要在第一次 configure 之前设置，
# 最可靠的方式是命令行：
#   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=...
#
# 这里保留你原来的“从环境变量 VCPKG_ROOT 推导”的逻辑，
# 但只在用户没有手动指定 toolchain 时尝试设置。

# if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
    CACHE FILEPATH "Vcpkg toolchain file")
# endif()

# 你原来注释掉的 chainload 示例（保留作为说明）
# set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/toolchain/aarch64-linux-gnu.cmake")
