# =========================
# Toolchain.cmake
# - vcpkg / toolchain 相关逻辑
# =========================
#
# 因为如何在build.rs里设置CMAKE_TOOLCHAIN_FILE会导致cmake这个crate短路掉c compiler的设定。
# 因此只能在这里设置。
#

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
      CACHE FILEPATH "Vcpkg toolchain file")
endif()
