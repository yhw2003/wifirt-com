#include "print_hello.h"
#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

static void format_ts(const struct timeval *tv, char *out, size_t out_sz) {
    time_t t = (time_t)tv->tv_sec;
    struct tm tmv;
    localtime_r(&t, &tmv);
    snprintf(out, out_sz,
             "%04d-%02d-%02d %02d:%02d:%02d.%06ld",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
             (long)tv->tv_usec);
}

static void print_ipv4_tuple(const uint8_t *ip, int caplen) {
    if (caplen < 20) return;

    uint8_t ver_ihl = ip[0];
    uint8_t ver = (uint8_t)(ver_ihl >> 4);
    uint8_t ihl = (uint8_t)((ver_ihl & 0x0F) * 4);
    if (ver != 4 || ihl < 20 || caplen < ihl) return;

    uint8_t proto = ip[9];

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip + 12, src, sizeof(src));
    inet_ntop(AF_INET, ip + 16, dst, sizeof(dst));

    const uint8_t *l4 = ip + ihl;
    int l4len = caplen - ihl;

    if (proto == IPPROTO_TCP && l4len >= 4) {
        uint16_t sport = read_be16(l4);
        uint16_t dport = read_be16(l4 + 2);
        printf("IPv4 TCP %s:%u -> %s:%u", src, sport, dst, dport);
    } else if (proto == IPPROTO_UDP && l4len >= 4) {
        uint16_t sport = read_be16(l4);
        uint16_t dport = read_be16(l4 + 2);
        printf("IPv4 UDP %s:%u -> %s:%u", src, sport, dst, dport);
    } else if (proto == IPPROTO_ICMP) {
        printf("IPv4 ICMP %s -> %s", src, dst);
    } else {
        printf("IPv4 proto=%u %s -> %s", (unsigned)proto, src, dst);
    }
}

static void print_ipv6_tuple(const uint8_t *ip, int caplen) {
    if (caplen < 40) return;

    uint8_t ver = (uint8_t)(ip[0] >> 4);
    if (ver != 6) return;

    uint8_t next = ip[6];

    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip + 8, src, sizeof(src));
    inet_ntop(AF_INET6, ip + 24, dst, sizeof(dst));

    const uint8_t *l4 = ip + 40;
    int l4len = caplen - 40;

    // 简化：不解析 IPv6 扩展头
    if (next == IPPROTO_TCP && l4len >= 4) {
        uint16_t sport = read_be16(l4);
        uint16_t dport = read_be16(l4 + 2);
        printf("IPv6 TCP %s:%u -> %s:%u", src, sport, dst, dport);
    } else if (next == IPPROTO_UDP && l4len >= 4) {
        uint16_t sport = read_be16(l4);
        uint16_t dport = read_be16(l4 + 2);
        printf("IPv6 UDP %s:%u -> %s:%u", src, sport, dst, dport);
    } else if (next == IPPROTO_ICMPV6) {
        printf("IPv6 ICMPv6 %s -> %s", src, dst);
    } else {
        printf("IPv6 next=%u %s -> %s", (unsigned)next, src, dst);
    }
}

static int try_set_dlt_raw(pcap_t *h) {
    int *dlts = NULL;
    int n = pcap_list_datalinks(h, &dlts);
    if (n <= 0 || dlts == NULL) return 0;

    int ok = 0;
    for (int i = 0; i < n; i++) {
        if (dlts[i] == DLT_RAW) {
            if (pcap_set_datalink(h, DLT_RAW) == 0) ok = 1;
            break;
        }
    }
    pcap_free_datalinks(dlts);
    return ok;
}

int print_hello(int argc, char **argv) {
    const char *dev = (argc >= 2) ? argv[1] : "lo";
    const char *filter_exp = (argc >= 3) ? argv[2] : "(host 127.0.0.1 or host ::1)";

    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    pcap_t *h = pcap_create(dev, errbuf);
    if (!h) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        return 1;
    }

    pcap_set_snaplen(h, 262144);
    pcap_set_promisc(h, 1);
    pcap_set_timeout(h, 1000);

#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
    // 若你系统/头文件支持可打开；不支持也没关系
    pcap_set_immediate_mode(h, 1);
#endif

    int rc = pcap_activate(h);
    if (rc != 0) {
        fprintf(stderr, "pcap_activate failed: %s\n", pcap_statustostr(rc));
        pcap_close(h);
        return 1;
    }

    int raw_ok = try_set_dlt_raw(h);
    int dlt = pcap_datalink(h);
    const char *dlt_name = pcap_datalink_val_to_name(dlt);

    printf("Device: %s\n", dev);
    printf("Filter: %s\n", filter_exp);
    printf("DLT: %d%s%s\n", dlt,
           dlt_name ? " (" : "",
           dlt_name ? dlt_name : "");
    if (dlt_name) printf(")\n");
    if (raw_ok) printf("DLT_RAW enabled.\n");
    printf("Capturing... (Ctrl+C to stop)\n");

    struct bpf_program fp;
    memset(&fp, 0, sizeof(fp));

    if (pcap_compile(h, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(h));
        pcap_close(h);
        return 1;
    }
    if (pcap_setfilter(h, &fp) != 0) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(h));
        pcap_freecode(&fp);
        pcap_close(h);
        return 1;
    }
    pcap_freecode(&fp);

    while (1) {
        struct pcap_pkthdr *header = NULL;
        const u_char *data = NULL;

        int r = pcap_next_ex(h, &header, &data);
        if (r == 0) continue; // timeout
        if (r == PCAP_ERROR) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(h));
            break;
        }
        if (r == PCAP_ERROR_BREAK) break;

        char ts[64];
        format_ts(&header->ts, ts, sizeof(ts));

        printf("[%s] len=%u caplen=%u ", ts, header->len, header->caplen);

        const uint8_t *p = (const uint8_t *)data;
        int caplen = (int)header->caplen;

        if (dlt == DLT_RAW) {
            if (caplen >= 1 && ((p[0] >> 4) == 4)) {
                print_ipv4_tuple(p, caplen);
            } else if (caplen >= 1 && ((p[0] >> 4) == 6)) {
                print_ipv6_tuple(p, caplen);
            } else {
                printf("RAW unknown");
            }
        } else {
            // 为了避免不同系统 loopback 的“伪链路头”差异，这里不做硬解析
            printf("Non-RAW DLT=%d (not decoded in this minimal demo)", dlt);
        }

        printf("\n");
    }

    pcap_close(h);
    return 0;
}
