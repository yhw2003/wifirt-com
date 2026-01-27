get_filename_component(PROJECT_DIR_NAME ${CMAKE_SOURCE_DIR} NAME)
cmake_minimum_required(VERSION 3.15)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 17)

# set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/toolchain/aarch64-linux-gnu.cmake")

set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")

project(${PROJECT_DIR_NAME} LANGUAGES C CXX)

find_package(fmt REQUIRED)

add_library(pcap-core STATIC "src/print_hello.c")

# 优先走 pkg-config（Linux 上最稳）
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET IMPORTED_TARGET libpcap)
endif()

if(TARGET PkgConfig::PCAP)
    target_link_libraries(pcap-core PRIVATE PkgConfig::PCAP)
    target_compile_definitions(pcap-core PRIVATE HAVE_PCAP_PKGCONFIG=1)
else()
    # 兜底：走 find_path / find_library（配合 vcpkg toolchain 一般也能找到）
    find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)

    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "Could not find libpcap. Try configuring with vcpkg toolchain:\n"
            "  -DCMAKE_TOOLCHAIN_FILE=$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake\n"
            "Or ensure pkg-config can find libpcap (module: libpcap)."
        )
    endif()

    target_include_directories(pcap-core PRIVATE "${PCAP_INCLUDE_DIR}")
    target_link_libraries(pcap-core PRIVATE "${PCAP_LIBRARY}")
endif()

target_include_directories(pcap-core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)



install(TARGETS pcap-core
ARCHIVE DESTINATION lib
LIBRARY DESTINATION lib
RUNTIME DESTINATION bin
)

set(_vcpkg_lib_dir "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib")
install(FILES "${_vcpkg_lib_dir}/libpcap.a" DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
