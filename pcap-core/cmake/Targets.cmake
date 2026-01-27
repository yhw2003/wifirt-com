# =========================
# Targets.cmake
# - 定义本项目的库/可执行文件 target
# =========================

add_library(pcap-core STATIC
    "src/print_hello.c"
)

# 公共头文件目录：对外暴露 include/
target_include_directories(pcap-core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# 链接第三方依赖
# - pcap::pcap：来自 Dependencies.cmake，统一封装
# - fmt::fmt：你原来 find_package(fmt REQUIRED) 但没用上，这里规范化链接（如果暂时不用可注释掉）
target_link_libraries(pcap-core
    PRIVATE
        pcap::pcap
        fmt::fmt
)
