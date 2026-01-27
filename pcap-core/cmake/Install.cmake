# =========================
# Install.cmake
# - 统一安装规则
# =========================

install(TARGETS pcap-core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# 安装 public headers
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/"
    DESTINATION include
)

# 你原来“强行安装 vcpkg 里的 libpcap.a”：
#   install(FILES "${_vcpkg_lib_dir}/libpcap.a" DESTINATION lib)
#
# 说明：
# 1) 这在多数项目里并不推荐：依赖库的安装通常由包管理器/系统负责
# 2) 并且当使用动态库或不同 triplet/配置（debug/release）时容易出错
#
# 如果你确实需要把静态依赖一起打包安装，可以保留，但建议做成可选项并做健壮性判断。

option(INSTALL_VCPKG_PCAP_STATIC "Install vcpkg's libpcap.a into install prefix" ON)

if(INSTALL_VCPKG_PCAP_STATIC)
    if(DEFINED VCPKG_INSTALLED_DIR AND DEFINED VCPKG_TARGET_TRIPLET)
        set(_vcpkg_lib_dir "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib")
        set(_pcap_a "${_vcpkg_lib_dir}/libpcap.a")

        if(EXISTS "${_pcap_a}")
            install(FILES "${_pcap_a}" DESTINATION lib)
        else()
            message(WARNING "INSTALL_VCPKG_PCAP_STATIC=ON but not found: ${_pcap_a}")
        endif()
    else()
        message(WARNING "INSTALL_VCPKG_PCAP_STATIC=ON but VCPKG_* vars are not defined.")
    endif()
endif()
