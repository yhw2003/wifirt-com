#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Inject a raw 802.11 frame (with radiotap header) on `dev`.
 *
 * @param dev interface name (e.g., "wlp4s0mon")
 * @param buf frame bytes (radiotap + 802.11)
 * @param len buffer length
 * @return >=0 bytes injected; negative on error.
 */
int pcap_send_frame(const char *dev, const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
