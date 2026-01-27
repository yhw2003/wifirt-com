# =========================
# Dependencies.cmake
# - 统一查找第三方依赖，并尽量生成规范的 imported target
# =========================

# ---- fmt ----
# find_package(fmt REQUIRED) 会提供 fmt::fmt target（常见情况）
find_package(fmt REQUIRED)

# ---- libpcap ----
# 目标：无论通过 pkg-config 还是 find_path/find_library，都提供统一 target：pcap::pcap

# 优先使用 pkg-config（Linux 上最稳）
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    # 生成 PkgConfig::PCAP imported target（若找到 libpcap.pc）
    pkg_check_modules(PCAP QUIET IMPORTED_TARGET libpcap)
endif()

if(TARGET PkgConfig::PCAP)
    # 统一别名：pcap::pcap
    add_library(pcap::pcap INTERFACE IMPORTED)
    target_link_libraries(pcap::pcap INTERFACE PkgConfig::PCAP)

    # 用于调试/条件编译的宏（保持你原来逻辑）
    target_compile_definitions(pcap::pcap INTERFACE HAVE_PCAP_PKGCONFIG=1)
else()
    # 兜底：find_path / find_library（配合 vcpkg toolchain 通常也能找到）
    find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)

    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "Could not find libpcap.\n"
            "Try configuring with vcpkg toolchain:\n"
            "  -DCMAKE_TOOLCHAIN_FILE=$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake\n"
            "Or ensure pkg-config can find libpcap (module: libpcap)."
        )
    endif()

    # 创建一个 imported library target，提供 include + link 信息
    add_library(pcap::pcap UNKNOWN IMPORTED)
    set_target_properties(pcap::pcap PROPERTIES
        IMPORTED_LOCATION "${PCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
    )
endif()
