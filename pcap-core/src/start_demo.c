#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#pragma pack(push, 1)
// Radiotap 头：我们只需要 length 字段来跳过 radiotap
typedef struct {
  uint8_t it_version;
  uint8_t it_pad;
  uint16_t it_len;     // little-endian
  uint32_t it_present; // 后面可能还有更多 present bitmap
} radiotap_hdr_t;

// 802.11 MAC header（管理帧常见为 24 字节）
typedef struct {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t seq_ctrl;
} ieee80211_hdr_t;
#pragma pack(pop)

static uint16_t le16(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void print_ssid(const uint8_t *ssid, uint8_t len) {
  if (len == 0) {
    printf("SSID: <hidden>\n");
    return;
  }
  // SSID 最多 32 字节
  if (len > 32)
    len = 32;

  // 可能包含不可打印字符，这里做安全输出
  printf("SSID: ");
  for (uint8_t i = 0; i < len; i++) {
    uint8_t c = ssid[i];
    if (c >= 32 && c <= 126)
      putchar(c);
    else
      putchar('.');
  }
  putchar('\n');
}

static void handle_pkt(u_char *user, const struct pcap_pkthdr *h,
                       const u_char *bytes) {
  (void)user;

  if (h->caplen < sizeof(radiotap_hdr_t))
    return;

  // Radiotap length
  uint16_t rt_len = le16(bytes + 2);
  if (rt_len >= h->caplen)
    return;

  const uint8_t *p = bytes + rt_len;
  size_t remain = h->caplen - rt_len;

  if (remain < sizeof(ieee80211_hdr_t))
    return;

  const ieee80211_hdr_t *hdr = (const ieee80211_hdr_t *)p;

  uint16_t fc = hdr->frame_control; // little-endian in memory on x86; here
                                    // assume little-endian host
  uint8_t type = (fc >> 2) & 0x3;
  uint8_t subtype = (fc >> 4) & 0xF;

  // 只处理管理帧 type=0，且 Beacon(8) 或 Probe Response(5)
  if (type != 0)
    return;
  if (!(subtype == 8 || subtype == 5))
    return;

  // 管理帧 header 通常 24 字节，后面是 fixed params（Beacon/ProbeResp 为 12
  // 字节）
  size_t hdr_len = 24;
  size_t fixed_len = 12;

  if (remain < hdr_len + fixed_len)
    return;

  const uint8_t *ies = p + hdr_len + fixed_len;
  size_t ies_len = remain - (hdr_len + fixed_len);

  // 解析 Tagged Parameters: [id][len][value...]
  size_t off = 0;
  while (off + 2 <= ies_len) {
    uint8_t id = ies[off];
    uint8_t len = ies[off + 1];
    off += 2;

    if (off + len > ies_len)
      break;

    if (id == 0) { // SSID parameter set
      print_ssid(ies + off, len);
      return; // 一个帧里 SSID IE 通常只出现一次
    }
    off += len;
  }
}

int start_demo() {
  const char *dev = "wlp4s0mon";
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *handle = pcap_open_live(dev, 2048, 1, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
    return 1;
  }

  // 尽量要求抓到 Radiotap + 802.11 原始帧
  // monitor 接口通常默认就是 DLT_IEEE802_11_RADIO
  int dlt = pcap_datalink(handle);
  if (dlt != DLT_IEEE802_11_RADIO) {
    fprintf(stderr,
            "Warning: datalink type is %d, not DLT_IEEE802_11_RADIO(127). "
            "Parsing may fail.\n",
            dlt);
  }

  // BPF 过滤：只抓 beacon 和 probe response（语法和 tcpdump 类似）
  struct bpf_program fp;
  const char *filter =
      "wlan type mgt subtype beacon or wlan type mgt subtype probe-resp";
  if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
    if (pcap_setfilter(handle, &fp) != 0) {
      fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
    }
    pcap_freecode(&fp);
  } else {
    fprintf(stderr, "pcap_compile failed (filter ignored): %s\n",
            pcap_geterr(handle));
  }

  printf("Listening on %s ... (Ctrl+C to stop)\n", dev);
  pcap_loop(handle, -1, handle_pkt, NULL);

  pcap_close(handle);
  return 0;
}
