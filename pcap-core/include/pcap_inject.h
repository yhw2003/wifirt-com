#pragma once

#include <stddef.h>
#include <stdint.h>

#include "pcap_handle.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Inject a raw 802.11 frame (with radiotap header) using an opened handle.
 *
 * @param handle opened handle from pcap_handle_open
 * @param buf frame bytes (radiotap + 802.11)
 * @param len buffer length
 * @return >=0 bytes injected; negative on error.
 */
int pcap_send_frame(pcap_handle_t *handle, const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
