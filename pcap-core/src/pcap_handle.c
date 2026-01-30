#include "pcap_handle.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

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

int pcap_handle_next(pcap_handle_t *handle, pcap_packet_view_t *out) {
  if (!handle || !handle->pcap || !out) {
    return -1;
  }

  struct pcap_pkthdr *hdr = NULL;
  const u_char *bytes = NULL;
  int ret = pcap_next_ex(handle->pcap, &hdr, &bytes);
  if (ret == 1) {
    out->data = bytes;
    out->caplen = (uint32_t)hdr->caplen;
    out->len = (uint32_t)hdr->len;
    out->ts_sec = (uint64_t)hdr->ts.tv_sec;
    out->ts_usec = (uint32_t)hdr->ts.tv_usec;
    return 0;
  }
  if (ret == 0) {
    return 1; // timeout
  }
  if (ret == -2) {
    return -2; // EOF (offline capture)
  }
  fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(handle->pcap));
  return -3;
}
