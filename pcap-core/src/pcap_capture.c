#include "pcap_capture.h"
#include "pcap_handle.h"

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

  pcap_handle_t *handle = pcap_handle_open(dev, snaplen, promisc, timeout_ms);
  if (!handle) {
    return -2;
  }

  int dlt = pcap_handle_get_dlt(handle);
  if (dlt != DLT_IEEE802_11_RADIO) {
    fprintf(stderr,
            "Warning: datalink type=%d (expected DLT_IEEE802_11_RADIO=127). "
            "Parsing may fail.\n",
            dlt);
  }

  if (filter && filter[0] != '\0') {
    pcap_handle_set_filter(handle, filter);
  }

  pcap_cb_ctx_t ctx = {cb, user};
  int ret = pcap_loop(handle->pcap, -1, pcap_forward_cb, (u_char *)&ctx);
  pcap_handle_close(handle);
  return ret;
}
