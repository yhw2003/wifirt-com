# 调整网卡工作模式

## 切换到monitor模式
```bash
ip link set <wlan> down
iw dev <wlan> set type monitor
ip linl set <wlan> up
```
或者使用`aircrack工具`
```bash
airmon-ng start <wlan>
```
测试：
1. 监听
```bash
tcpdump -i wlp4s0 -s 0 -vv 
```
你应该看到的输出例如：
```
tcpdump: listening on <wlan>, link-type IEEE802_11_RADIO (802.11 plus radiotap header), snapshot length 262144 bytes
19:21:02.808669 1.0 Mb/s 2412 MHz 11b -80dBm signal 100 sq -78dBm signal antenna 0 -88dBm signal antenna 1 Clear-To-Send FF:FF:FF:FF:FF:FF:FF (oui Unknown) 
19:21:02.818867 1.0 Mb/s 2412 MHz 11b -82dBm signal 100 sq -78dBm signal antenna 0 -88dBm signal antenna 1 Beacon () [1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0 Mbit] ESS CH: 1, PRIVACY
19:21:02.851810 1.0 Mb/s 2412 MHz 11b -80dBm signal 100 sq -74dBm signal antenna 0 -84dBm signal antenna 1 Clear-To-Send FF:FF:FF:FF:FF:FF:FF (oui Unknown) 
```
```bash
aireplay-ng -9 <wlan>
```
你应该看到的输出例如：
```
19:23:27  Trying broadcast probe requests...
19:23:28  Injection is working!
19:23:29  Found 18 APs

19:23:29  Trying directed probe requests...
19:23:29  FF:FF:FF:FF:FF:FF:FF - channel: 1 - 'XX_WIFI'
19:23:30  Ping (min/avg/max): 1.732ms/5.274ms/24.079ms Power: -75.17
19:23:30  24/30:  80%
```


## 固定网卡最大功率
```bash
iwconfig wlan0 txpower 30
```
(论坛这么说，但是我测试的发现如果这样设置网卡反而不能正常工作)
同时编辑`/etc/modprobe.d/8812au.conf`
```
options 88x2au_ohd rtw_tx_pwr_lmt_enable=0   # 禁用功率限制表
options 88x2au_ohd rtw_tx_pwr_by_rate=0      # 禁用根据速率调整功率
```