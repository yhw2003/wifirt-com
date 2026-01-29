# Frame Inject 通信协议与注入方式

本项目在 `src/decode.rs` 中支持解析自定义 payload。为保证接收端能够稳定识别，请按下面格式和注入方式构造 802.11 帧。

## Payload 格式（放在 802.11 帧体的最前面）

```
Offset  Size  描述
0       4     魔术字节: "WFRT" (0x57 0x46 0x52 0x54)
4       2     payload 长度: u16，小端
6       N     payload 内容
```

- 接收端只在 payload 以 `WFRT` 开头时解析。
- 如果长度字段超过实际剩余数据，会被忽略。
- 建议最大 payload 不超过 MTU，避免驱动丢包。

## 802.11 帧建议

- **帧类型**：Data 或 QoS Data。
- **ToDS/FromDS**：均为 0（独立链路，避免关联需求）。
- **Addr1 (RA/DA)**：广播 `ff:ff:ff:ff:ff:ff` 或对端 MAC。
- **Addr2 (TA/SA)**：本机 MAC。
- **Addr3 (BSSID)**：可填 `ff:ff:ff:ff:ff:ff` 或与 Addr2 相同。
- **FCS**：通常由网卡/驱动自动填充，不需要手动追加。

## Radiotap 头

多数驱动要求在 monitor 注入时携带 radiotap 头。最小可用头如下：

```
00 00 08 00 00 00 00 00
```

表示：version=0、len=8、present=0。若需指定速率/信道，可扩展 radiotap 字段。

## 注入示例（Python + Scapy）

```python
from scapy.all import RadioTap, Dot11, Dot11QoS, sendp, hexdump

payload = b"WFRT" + (4).to_bytes(2, "little") + b"\xde\xad\xbe\xef"
frame = (
    RadioTap()
    / Dot11(type=2, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
            addr2="02:11:22:33:44:55", addr3="ff:ff:ff:ff:ff:ff")
    / Dot11QoS()
    / payload
)
sendp(frame, iface="wlp4s0mon", count=1, inter=0.1, verbose=False)
```

## 注入示例（C + libpcap）

```c
// buf = radiotap(8) + 802.11 header + payload
// payload = "WFRT" + len(2) + data
pcap_inject(handle, buf, buf_len);
```

## 接收端行为

接收端会在解析完 802.11 头之后，检查 payload 前 6 字节是否是 `WFRT` + 长度。匹配则打印 `WFRT:` 以及 payload 内容（十六进制）。
