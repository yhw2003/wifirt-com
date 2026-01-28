#include "pcap_capture.h"

#include <pcap.h>
#include <stdio.h>

typedef struct {
  pcap_packet_cb cb;
  void *user;
} pcap_cb_ctx_t;

static void pcap_forward_cb(u_char *user, const struct pcap_pkthdr *h,
                            const u_char *bytes) {
  pcap_cb_ctx_t *ctx = (pcap_cb_ctx_t *)user;
  if (!ctx || !ctx->cb || !h || !bytes)
    return;

  ctx->cb(bytes, (uint32_t)h->caplen, (uint32_t)h->len, (uint64_t)h->ts.tv_sec,
          (uint32_t)h->ts.tv_usec, ctx->user);
}

int pcap_start_capture(const char *dev, const char *filter, int snaplen,
                       int promisc, int timeout_ms, pcap_packet_cb cb,
                       void *user) {
  if (!dev || !cb) {
    fprintf(stderr, "pcap_start_capture: invalid args\n");
    return -1;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  int snap = snaplen > 0 ? snaplen : 4096;
  int prom = promisc ? 1 : 0;
  int to_ms = timeout_ms >= 0 ? timeout_ms : 1000;

  pcap_t *handle = pcap_open_live(dev, snap, prom, to_ms, errbuf);
  if (!handle) {
    fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
    return -2;
  }

  int dlt = pcap_datalink(handle);
  if (dlt != DLT_IEEE802_11_RADIO) {
    fprintf(stderr,
            "Warning: datalink type=%d (expected DLT_IEEE802_11_RADIO=127). "
            "Parsing may fail.\n",
            dlt);
  }

  if (filter && filter[0] != '\0') {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
      pcap_setfilter(handle, &fp);
      pcap_freecode(&fp);
    } else {
      fprintf(stderr, "pcap_compile failed for filter: %s\n", filter);
    }
  }

  pcap_cb_ctx_t ctx = {cb, user};
  int ret = pcap_loop(handle, -1, pcap_forward_cb, (u_char *)&ctx);
  pcap_close(handle);
  return ret;
}
