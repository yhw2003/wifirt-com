cmake_minimum_required(VERSION 3.15)

# 以源码根目录名作为 project 名称（保持你原来的行为）
get_filename_component(PROJECT_DIR_NAME "${CMAKE_SOURCE_DIR}" NAME)

project(${PROJECT_DIR_NAME} LANGUAGES C)

# 统一把自定义 cmake 模块放到 cmake/ 下
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# 1. 全局选项、编译标准等
include(Options)

# 2. 工具链 / vcpkg（注意：通常 toolchain 更推荐通过命令行 -DCMAKE_TOOLCHAIN_FILE=... 传入）
include(Toolchain)

# 3. 外部依赖（fmt、libpcap）
include(Dependencies)

# 4. 本项目目标（pcap-core）
include(Targets)

# 5. 安装规则
include(Install)
