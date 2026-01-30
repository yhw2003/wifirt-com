#pragma once

#include <pcap.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcap_handle {
  pcap_t *pcap;
} pcap_handle_t;

typedef void (*pcap_packet_cb)(const uint8_t *data, uint32_t caplen,
                               uint32_t len, uint64_t ts_sec, uint32_t ts_usec,
                               void *user);

pcap_handle_t *pcap_handle_open(const char *dev, int snaplen, int promisc,
                                int timeout_ms);
void pcap_handle_close(pcap_handle_t *handle);
int pcap_handle_set_filter(pcap_handle_t *handle, const char *filter);
int pcap_handle_get_dlt(const pcap_handle_t *handle);

int pcap_start_capture(const char *dev, const char *filter, int snaplen,
                       int promisc, int timeout_ms, pcap_packet_cb cb,
                       void *user);

#ifdef __cplusplus
}
#endif
