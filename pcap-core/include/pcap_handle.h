#pragma once

#include <pcap.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcap_handle {
  pcap_t *pcap;
} pcap_handle_t;

typedef struct pcap_packet_view {
  const uint8_t *data;
  uint32_t caplen;
  uint32_t len;
  uint64_t ts_sec;
  uint32_t ts_usec;
} pcap_packet_view_t;

pcap_handle_t *pcap_handle_open(const char *dev, int snaplen, int promisc,
                                int timeout_ms);
void pcap_handle_close(pcap_handle_t *handle);
int pcap_handle_set_filter(pcap_handle_t *handle, const char *filter);
int pcap_handle_get_dlt(const pcap_handle_t *handle);

/**
 * Blocking read the next packet.
 *
 * @param handle opened handle
 * @param out filled on success; data pointer is valid until the next call on
 *            the same handle
 * @return 0 on success, 1 on timeout (pcap_next_ex returned 0), -2 on EOF,
 *         negative on error.
 */
int pcap_handle_next(pcap_handle_t *handle, pcap_packet_view_t *out);

#ifdef __cplusplus
}
#endif
