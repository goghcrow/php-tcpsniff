#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <pcap/sll.h>
#include <net/ethernet.h>
#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include "sniff.h"

struct tcpsniff_opt;

struct tcpsniff_t
{
    /* tcpsniff_opt {{{ */
    int snaplen;       /* 最大捕获长度               */
    int pkt_cnt_limit; /* 限制捕获pkt数量0:unlimited */
    int timeout_limit; /* 多少ms从内核copy一次数据    */
    char *device;      /* 网卡                      */
    char *filter_exp;  /* bpf 表达式                */
    void *ud;
    /* }}} */

    int dl_type;             /* data link type           */
    int dl_hdr_offset;       /* dlhdr大小 决定iphdr偏移    */
    bpf_u_int32 ip;          /* 网卡 ip                   */
    bpf_u_int32 subnet_mask; /* 网卡 子网掩码              */
    pcap_t *handle;
    tcpsniff_pkt_handler pkt_handler;
};

static bool sniffing = 0;

static void pcap_pkt_handler(struct tcpsniff_t *sniff, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt)
{
    if (pkt_hdr->caplen != pkt_hdr->len)
    {
        fprintf(stderr, "Packet length is %d bytes, but only %d bytes captured\n", pkt_hdr->len, pkt_hdr->caplen);
        // pcap_close(sniff->handle);
        // exit(1);
    }

    u_int16_t protocol = ETHERTYPE_IP;
    switch (sniff->dl_type)
    {
    case DLT_NULL: // 0
        // FIXME support PF_LOCAL ?
        if (*(int32_t *)pkt != PF_INET) {
            protocol = 0;
        }
        break;
    case DLT_RAW: // 12
        break;
    case DLT_EN10MB: // 1
    {
        struct ether_header *ether_hdr = (struct ether_header *)pkt;
        protocol = ntohs(ether_hdr->ether_type);
    }
    break;
    case DLT_LINUX_SLL: // 113
    {
        struct sll_header *ssl_hdr = (struct sll_header *)pkt;
        protocol = ntohs(ssl_hdr->sll_protocol);
    }
    break;
    }

    // 忽略非ip
    if (protocol != ETHERTYPE_IP)
    {
        return;
    }

    /*
    {
        const u_char *ip_hdr = pkt + sniff->dl_hdr_offset;
        // 网络字节序ip_hl在第一个字节的低位4bit, 见README.md
        // ip_hl 代表 多少个 32bit segment, * 4才为bytes数
        int ip_hdr_len = ((*ip_hdr) & 0x0F) * 4;
        u_char protocol = *(ip_hdr + 9); // 第10个字节为protocol, 见README.md

        // 忽略非tcp pkt
        if (protocol != IPPROTO_TCP)
        {
            return;
        }

        const u_char *tcp_hdr = ip_hdr + ip_hdr_len;
        // 网络字节序下th_off在tcp_hdr偏移12字节(第13字节)高位4bit, 见README.md
        // 需要将高位4bit右移到低位, th_off 也表示多少个 32bit word
        int tcp_hdr_len = (((*(tcp_hdr + 12)) & 0xF0) >> 4) * 4;

        int total_hdr_len = sniff->dl_hdr_offset + ip_hdr_len + tcp_hdr_len;
        int payload_len = pkt_hdr->caplen - total_hdr_len;
        assert(payload_len >= 0);
        const u_char *payload = tcp_hdr + tcp_hdr_len;
        printf("ip_hdr_size=%d tcp_hdr_size=%d payload_size=%d\n", ip_hdr_len, tcp_hdr_len, payload_len);
    }
    */

    // 或者 强制类型转换, 不需要自己算, 直接读, 这里为什么不用自己ntoh转字节序????????

    struct ip *ip_hdr = (struct ip *)(pkt + sniff->dl_hdr_offset);
    int ip_hdr_sz = ip_hdr->ip_hl * 4;

    // 忽略非tcp pkt
    if (ip_hdr->ip_p != IPPROTO_TCP)
    {
        return;
    }
    struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt + sniff->dl_hdr_offset + ip_hdr_sz);
    int tcp_hdr_sz = tcp_hdr->th_off * 4;
    int total_hdr_sz = sniff->dl_hdr_offset + ip_hdr_sz + tcp_hdr_sz;
    int payload_sz = pkt_hdr->caplen - total_hdr_sz;
    assert(payload_sz >= 0);
    const u_char *payload = pkt + total_hdr_sz;
    // printf("ip_hdr_size=%d tcp_hdr_size=%d payload_size=%d\n", ip_hdr_sz, tcp_hdr_sz, payload_sz);
    sniff->pkt_handler(sniff->ud, pkt_hdr, ip_hdr, tcp_hdr, payload, payload_sz);
}

bool tcpsniff(struct tcpsniff_opt *opt, tcpsniff_pkt_handler pkt_handler)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct tcpsniff_t sniff;
    memset(&sniff, 0, sizeof(sniff));
    memcpy(&sniff, opt, sizeof(*opt));
    sniff.pkt_handler = pkt_handler;
    
    // Get information for device 查询网卡IP地址与子网掩码
    // device = any ip与mask 均为0.0.0.0
    if (pcap_lookupnet(sniff.device, &sniff.ip, &sniff.subnet_mask, errbuf) == -1)
    {
        fprintf(stderr, "ERROR in pcap_lookupnet, cound not get info for device: %s\n", errbuf);
        sniff.ip = 0;
        sniff.subnet_mask = 0;
    }

    if (sniff.ip)
    {
        // FIXME INET6
        char ip_buf[INET_ADDRSTRLEN];
        char mask_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sniff.ip, ip_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &sniff.subnet_mask, mask_buf, INET_ADDRSTRLEN);
        printf("%s ip=%s mask=%s\n", sniff.device, ip_buf, mask_buf);
    }

    sniff.handle = pcap_open_live(sniff.device, sniff.snaplen, sniff.pkt_cnt_limit, sniff.timeout_limit, errbuf);
    if (sniff.handle == NULL)
    {
        fprintf(stderr, "ERROR in pcap_open_live, cound not open %s: %s\n", sniff.device, errbuf);
        return false;
    }

    // data link type 参见 #include <pcap/bpf.h>
    sniff.dl_type = pcap_datalink(sniff.handle);
    // fprintf(stderr, "datalink type is %d\n", sniff.dl_type);
    switch (sniff.dl_type)
    {
    case DLT_NULL: /* BSD loopback encapsulation */
        sniff.dl_hdr_offset = 4; // 4byte 本地字节序, 值为PF_* socket.h 用来说明pkt的网络层协议
        break;
    case DLT_RAW: // 无链路层hdr
        sniff.dl_hdr_offset = 0;
        break;
    case DLT_EN10MB: // 1 : ether网 >= 10M
        sniff.dl_hdr_offset = 14;
        break;
    case DLT_LINUX_SLL: // 12 : device = any 时链路层 hdr
        sniff.dl_hdr_offset = SLL_HDR_LEN;
        break;
    default:
        fprintf(stderr, "链路层类型未知(%d)\n", sniff.dl_type);
        return false;
    }

    struct bpf_program filter;
    // Compiles the filter expression into a BPF filter program
    // if (pcap_compile(handle, &filter, sniff->filter_exp, 0, sniff->ip) == -1)
    if (pcap_compile(sniff.handle, &filter, sniff.filter_exp, 1, sniff.subnet_mask) == -1)
    {
        fprintf(stderr, "ERROR in pcap_compile: %s\n", pcap_geterr(sniff.handle));
        pcap_close(sniff.handle);
        return false;
    }

    // Load the fitler program into the pakcet capture device
    if (pcap_setfilter(sniff.handle, &filter) == -1)
    {
        fprintf(stderr, "ERROR in pcap_setfilter: %s\n", pcap_geterr(sniff.handle));
        pcap_close(sniff.handle);
        return false;
    }

    struct pcap_pkthdr *pkt_hdr = NULL;
    const u_char *pkt = NULL;
    int ret = 0;
    sniffing = true;
    while (sniffing)
    {
        ret = pcap_next_ex(sniff.handle, &pkt_hdr, &pkt);
        if (ret == 0)
        {
            continue; // timeout
        }
        if (ret == -1)
        {
            fprintf(stderr, "ERROR in pcap_next: %s\n", pcap_geterr(sniff.handle));
            pcap_close(sniff.handle);
            return false;
        }

        pcap_pkt_handler(&sniff, pkt_hdr, pkt);
    }

    return true;
}

void tcpsniff_exit()
{
    sniffing = false;
}