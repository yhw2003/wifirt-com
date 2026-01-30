#pragma once

#include <stdint.h>

#include "pcap_handle.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*pcap_packet_cb)(const uint8_t *data, uint32_t caplen,
                               uint32_t len, uint64_t ts_sec, uint32_t ts_usec,
                               void *user);

int pcap_start_capture(const char *dev, const char *filter, int snaplen,
                       int promisc, int timeout_ms, pcap_packet_cb cb,
                       void *user);

#ifdef __cplusplus
}
#endif
