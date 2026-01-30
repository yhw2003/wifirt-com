#include "pcap_inject.h"

#include <pcap.h>
#include <stdio.h>

int pcap_send_frame(const char *dev, const uint8_t *buf, size_t len) {
  if (!dev || !buf || len == 0) {
    fprintf(stderr, "pcap_send_frame: invalid args\n");
    return -1;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live(dev, 4096, 1, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
    return -2;
  }

  int ret = pcap_inject(handle, buf, len);
  if (ret < 0) {
    fprintf(stderr, "pcap_inject failed: %s\n", pcap_geterr(handle));
  }

  pcap_close(handle);
  return ret;
}
