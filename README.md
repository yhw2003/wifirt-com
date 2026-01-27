# wifirt-com
这是一个通过魔改wifi来发送和接受裸802.11报文的无连接的无线通讯方案。

## 适用于：
数字图传，低延时信令传递。有效通信距离会十分显著的优于wifi网络。

## Build
你需要安装rust工具链和目标平台的gcc，以及常用构建工具
  - `gcc`
  - `make`
  - `cmake`
  - `pkg-cofig`
  - `rustup`
  - `vcpkg`

``` shell
  cargo build
```
目前交叉编译只支持`aarch64-unknown-linux-gnu`