#include "pcap_inject.h"

#include <pcap.h>
#include <stdio.h>

int pcap_send_frame(pcap_handle_t *handle, const uint8_t *buf, size_t len) {
  if (!handle || !handle->pcap || !buf || len == 0) {
    fprintf(stderr, "pcap_send_frame: invalid args\n");
    return -1;
  }

  int ret = pcap_inject(handle->pcap, buf, len);
  if (ret < 0) {
    fprintf(stderr, "pcap_inject failed: %s\n", pcap_geterr(handle->pcap));
  }

  return ret;
}
