#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#pragma pack(push, 1)
typedef struct {
  uint8_t it_version;
  uint8_t it_pad;
  uint16_t it_len;     // little-endian
  uint32_t it_present; // little-endian, may extend via bit31
} radiotap_hdr_t;

typedef struct {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t seq_ctrl;
} ieee80211_hdr_t;
#pragma pack(pop)

static uint16_t le16(const void *vp) {
  const uint8_t *p = (const uint8_t *)vp;
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t le32(const void *vp) {
  const uint8_t *p = (const uint8_t *)vp;
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}
static uint64_t le64(const void *vp) {
  const uint8_t *p = (const uint8_t *)vp;
  return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}

static size_t align_up(size_t off, size_t a) {
  if (a == 0)
    return off;
  size_t r = off % a;
  return r ? (off + (a - r)) : off;
}

static void mac_to_str(const uint8_t m[6], char out[18]) {
  snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3],
           m[4], m[5]);
}

static const char *type_str(uint8_t t) {
  switch (t) {
  case 0:
    return "MGMT";
  case 1:
    return "CTRL";
  case 2:
    return "DATA";
  default:
    return "RSVD";
  }
}

static const char *mgmt_subtype_str(uint8_t st) {
  switch (st) {
  case 0:
    return "AssocReq";
  case 1:
    return "AssocResp";
  case 2:
    return "ReassocReq";
  case 3:
    return "ReassocResp";
  case 4:
    return "ProbeReq";
  case 5:
    return "ProbeResp";
  case 8:
    return "Beacon";
  case 10:
    return "Disassoc";
  case 11:
    return "Auth";
  case 12:
    return "Deauth";
  case 13:
    return "Action";
  default:
    return "MgmtOther";
  }
}

typedef struct {
  int has_rate;
  uint8_t rate_500kbps; // radiotap RATE: 500kbps units

  int has_channel;
  uint16_t chan_freq; // MHz
  uint16_t chan_flags;

  int has_dbm_signal;
  int8_t dbm_signal;

  int has_antenna;
  uint8_t antenna;

  int has_flags;
  uint8_t rt_flags;
} rt_meta_t;

/*
 * Minimal radiotap parser for common fields.
 * Radiotap present bits (index):
 *  0 TSFT (8, align 8)
 *  1 FLAGS (1, align 1)
 *  2 RATE (1, align 1)
 *  3 CHANNEL (4, align 2) [freq u16 + flags u16]
 *  5 DBM_ANTSIGNAL (1, align 1)
 * 11 ANTENNA (1, align 1)
 * If drivers add more fields, we skip them by walking bits with sizes.
 */
static int parse_radiotap(const uint8_t *pkt, size_t caplen, rt_meta_t *out,
                          uint16_t *rt_len_out) {
  memset(out, 0, sizeof(*out));
  if (caplen < sizeof(radiotap_hdr_t))
    return -1;

  const radiotap_hdr_t *rt = (const radiotap_hdr_t *)pkt;
  if (rt->it_version != 0)
    return -1;

  uint16_t rt_len = le16(&rt->it_len);
  if (rt_len > caplen || rt_len < sizeof(radiotap_hdr_t))
    return -1;

  // Read all present words (bit31 indicates more)
  size_t present_off = 4; // after version/pad/len (2+?) -> actually header
                          // starts at 0, present at offset 4
  // radiotap_hdr_t already includes it_present at offset 4
  size_t off = 8; // fields start after first present word
  uint32_t present_words[8];
  int pw = 0;

  uint32_t p = le32(pkt + present_off);
  present_words[pw++] = p;
  while (p & 0x80000000) {
    if (pw >= 8)
      break; // avoid runaway
    if (caplen < off + 4)
      return -1;
    p = le32(pkt + off);
    present_words[pw++] = p;
    off += 4;
  }

  // Now off points to first field after all present words
  size_t fields_off = off;

  // Helper to skip unknown fields by known size/alignment (common radiotap
  // layout) For bits beyond those, we won't parse; but must still advance
  // offset correctly if present. We'll define sizes/align for first 32 bits,
  // and ignore extended ones by best-effort.
  struct {
    uint8_t size;
    uint8_t align;
  } fmt[32] = {
      [0] = {8, 8},  // TSFT
      [1] = {1, 1},  // FLAGS
      [2] = {1, 1},  // RATE
      [3] = {4, 2},  // CHANNEL
      [4] = {2, 2},  // FHSS
      [5] = {1, 1},  // DBM_ANTSIGNAL
      [6] = {1, 1},  // DBM_ANTNOISE
      [7] = {2, 2},  // LOCK_QUALITY
      [8] = {2, 2},  // TX_ATTENUATION
      [9] = {2, 2},  // DB_TX_ATTENUATION
      [10] = {1, 1}, // DBM_TX_POWER
      [11] = {1, 1}, // ANTENNA
      [12] = {1, 1}, // DB_ANTSIGNAL
      [13] = {1, 1}, // DB_ANTNOISE
      [14] = {2, 2}, // RX_FLAGS
      [15] = {2, 2}, // TX_FLAGS
      [16] = {1, 1}, // RTS_RETRIES
      [17] = {1, 1}, // DATA_RETRIES
                     // others default 0,0
  };

  size_t cur = fields_off;

  for (int w = 0; w < pw; w++) {
    uint32_t word = present_words[w];
    for (int bit = 0; bit < 32; bit++) {
      if (bit == 31)
        continue; // extension indicator, not a field
      if (!(word & (1u << bit)))
        continue;

      uint8_t sz = (bit < 32) ? fmt[bit].size : 0;
      uint8_t al = (bit < 32) ? fmt[bit].align : 1;
      if (sz == 0) {
        // Unknown field present: can't safely parse/skip without full spec.
        // Best effort: stop parsing to avoid misalignment.
        // We still keep rt_len and return what we have.
        *rt_len_out = rt_len;
        return 0;
      }

      cur = align_up(cur, al);
      if (cur + sz > rt_len) { // must be within radiotap length
        *rt_len_out = rt_len;
        return 0;
      }

      const uint8_t *fp = pkt + cur;

      if (w == 0) { // only bits 0-30 are in first 32-bit present word; ok for
                    // our parsed bits
        switch (bit) {
        case 1:
          out->has_flags = 1;
          out->rt_flags = fp[0];
          break;
        case 2:
          out->has_rate = 1;
          out->rate_500kbps = fp[0];
          break;
        case 3:
          out->has_channel = 1;
          out->chan_freq = le16(fp);
          out->chan_flags = le16(fp + 2);
          break;
        case 5:
          out->has_dbm_signal = 1;
          out->dbm_signal = (int8_t)fp[0];
          break;
        case 11:
          out->has_antenna = 1;
          out->antenna = fp[0];
          break;
        default:
          break;
        }
      }

      cur += sz;
    }
  }

  *rt_len_out = rt_len;
  return 0;
}

static int freq_to_channel(uint16_t freq_mhz) {
  // Common mapping: 2.4GHz and 5GHz (basic)
  if (freq_mhz >= 2412 && freq_mhz <= 2472)
    return (freq_mhz - 2407) / 5;
  if (freq_mhz == 2484)
    return 14;
  if (freq_mhz >= 5000 && freq_mhz <= 5900)
    return (freq_mhz - 5000) / 5;
  return -1;
}

static void print_ssid_if_any(const uint8_t *p80211, size_t remain,
                              uint8_t type, uint8_t subtype) {
  // only MGMT Beacon/ProbeResp: fixed params 12 bytes after 24-byte hdr
  if (type != 0)
    return;
  if (!(subtype == 8 || subtype == 5))
    return;

  if (remain < 24 + 12)
    return;
  const uint8_t *ies = p80211 + 24 + 12;
  size_t ies_len = remain - (24 + 12);

  size_t off = 0;
  while (off + 2 <= ies_len) {
    uint8_t id = ies[off];
    uint8_t len = ies[off + 1];
    off += 2;
    if (off + len > ies_len)
      return;

    if (id == 0) {
      printf("  SSID: ");
      if (len == 0) {
        printf("<hidden>\n");
      } else {
        if (len > 32)
          len = 32;
        for (uint8_t i = 0; i < len; i++) {
          uint8_t c = ies[off + i];
          if (c >= 32 && c <= 126)
            putchar(c);
          else
            putchar('.');
        }
        putchar('\n');
      }
      return;
    }
    off += len;
  }
}

static void handle_pkt(u_char *user, const struct pcap_pkthdr *h,
                       const u_char *bytes) {
  (void)user;

  // ---- PCAP metadata ----
  char tbuf[64];
  struct tm tm;
  time_t sec = (time_t)h->ts.tv_sec;
  localtime_r(&sec, &tm);
  strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

  printf("=== Packet ===\n");
  printf("PCAP: time=%s.%06ld caplen=%u len=%u\n", tbuf, (long)h->ts.tv_usec,
         (unsigned)h->caplen, (unsigned)h->len);

  // ---- Radiotap metadata ----
  rt_meta_t rt;
  uint16_t rt_len = 0;
  if (parse_radiotap(bytes, h->caplen, &rt, &rt_len) == 0) {
    printf("Radiotap: len=%u", rt_len);

    if (rt.has_dbm_signal)
      printf(" rssi=%ddBm", rt.dbm_signal);

    if (rt.has_rate) {
      // RATE unit 500kbps
      double mbps = rt.rate_500kbps * 0.5;
      printf(" rate=%.1fMbps", mbps);
    }

    if (rt.has_channel) {
      int ch = freq_to_channel(rt.chan_freq);
      if (ch > 0)
        printf(" channel=%d", ch);
      printf(" freq=%uMHz", rt.chan_freq);
    }

    if (rt.has_antenna)
      printf(" ant=%u", rt.antenna);

    if (rt.has_flags)
      printf(" flags=0x%02x", rt.rt_flags);

    printf("\n");
  } else {
    printf("Radiotap: <parse failed>\n");
    return;
  }

  if (rt_len >= h->caplen)
    return;

  // ---- 802.11 metadata ----
  const uint8_t *p80211 = bytes + rt_len;
  size_t remain = h->caplen - rt_len;
  if (remain < sizeof(ieee80211_hdr_t))
    return;

  const ieee80211_hdr_t *hdr = (const ieee80211_hdr_t *)p80211;
  uint16_t fc = hdr->frame_control;

  uint8_t type = (fc >> 2) & 0x3;
  uint8_t subtype = (fc >> 4) & 0xF;

  uint8_t toDS = (fc >> 8) & 0x1;
  uint8_t fromDS = (fc >> 9) & 0x1;
  uint8_t retry = (fc >> 11) & 0x1;
  uint8_t pwrmgmt = (fc >> 12) & 0x1;
  uint8_t moredata = (fc >> 13) & 0x1;
  uint8_t protect = (fc >> 14) & 0x1;

  char a1[18], a2[18], a3[18];
  mac_to_str(hdr->addr1, a1);
  mac_to_str(hdr->addr2, a2);
  mac_to_str(hdr->addr3, a3);

  uint16_t seq = le16(&hdr->seq_ctrl);
  uint16_t frag = seq & 0xF;
  uint16_t seqno = (seq >> 4) & 0xFFF;

  printf("802.11: type=%s(%u) subtype=%u", type_str(type), type, subtype);
  if (type == 0)
    printf("(%s)", mgmt_subtype_str(subtype));
  printf(" ToDS=%u FromDS=%u Retry=%u Protected=%u PwrMgmt=%u MoreData=%u\n",
         toDS, fromDS, retry, protect, pwrmgmt, moredata);

  printf("ADDR: RA/DA=%s TA/SA=%s BSSID/3=%s\n", a1, a2, a3);
  printf("SEQ: seq=%u frag=%u duration=%u\n", seqno, frag,
         le16(&hdr->duration));

  // Optional: show SSID when present (Beacon/ProbeResp)
  print_ssid_if_any(p80211, remain, type, subtype);

  printf("\n");
}

int start_demo() {
  const char *dev = "wlp4s0mon";
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *handle = pcap_open_live(dev, 4096, 1, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
    return 1;
  }

  int dlt = pcap_datalink(handle);
  if (dlt != DLT_IEEE802_11_RADIO) {
    fprintf(stderr,
            "Warning: datalink type=%d (expected DLT_IEEE802_11_RADIO=127). "
            "Parsing may fail.\n",
            dlt);
  }

  // 这里不再只抓 Beacon/ProbeResp：改为抓所有 802.11 帧元数据
  // 如果你想过滤掉高流量数据帧，可改用例如：
  //   "wlan type mgt" 或 "wlan type mgt or wlan type ctrl"
  struct bpf_program fp;
  const char *filter = ""; // empty => no filter (all)
  if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);
  }

  printf("Listening on %s ... (Ctrl+C to stop)\n", dev);
  pcap_loop(handle, -1, handle_pkt, NULL);

  pcap_close(handle);
  return 0;
}
