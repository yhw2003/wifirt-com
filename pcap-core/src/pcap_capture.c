#include "pcap_capture.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

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

pcap_handle_t *pcap_handle_open(const char *dev, int snaplen, int promisc,
                                int timeout_ms) {
  if (!dev) {
    fprintf(stderr, "pcap_handle_open: invalid dev\n");
    return NULL;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  int snap = snaplen > 0 ? snaplen : 4096;
  int prom = promisc ? 1 : 0;
  int to_ms = timeout_ms >= 0 ? timeout_ms : 1000;

  pcap_t *pcap = pcap_open_live(dev, snap, prom, to_ms, errbuf);
  if (!pcap) {
    fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
    return NULL;
  }

  pcap_handle_t *handle = (pcap_handle_t *)malloc(sizeof(pcap_handle_t));
  if (!handle) {
    fprintf(stderr, "pcap_handle_open: OOM\n");
    pcap_close(pcap);
    return NULL;
  }

  handle->pcap = pcap;
  return handle;
}

void pcap_handle_close(pcap_handle_t *handle) {
  if (!handle) {
    return;
  }
  if (handle->pcap) {
    pcap_close(handle->pcap);
    handle->pcap = NULL;
  }
  free(handle);
}

int pcap_handle_set_filter(pcap_handle_t *handle, const char *filter) {
  if (!handle || !handle->pcap || !filter) {
    return -1;
  }
  struct bpf_program fp;
  if (pcap_compile(handle->pcap, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
    fprintf(stderr, "pcap_compile failed for filter: %s\n", filter);
    return -2;
  }
  if (pcap_setfilter(handle->pcap, &fp) != 0) {
    fprintf(stderr, "pcap_setfilter failed\n");
    pcap_freecode(&fp);
    return -3;
  }
  pcap_freecode(&fp);
  return 0;
}

int pcap_handle_get_dlt(const pcap_handle_t *handle) {
  if (!handle || !handle->pcap) {
    return -1;
  }
  return pcap_datalink(handle->pcap);
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
