#ifndef SNIFF_H
#define SNIFF_H

#include <pcap/pcap.h>
#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stddef.h>

/*
对pcap的简单封装 只抓tcp包
*/

struct tcpsniff_opt
{
    int snaplen;       /* 最大捕获长度               */
    int pkt_cnt_limit; /* 限制捕获pkt数量0:unlimited */
    int timeout_limit; /* 多少ms从内核copy一次数据    */
    char *device;      /* 网卡                      */
    char *filter_exp;  /* bpf 表达式                */
    void *ud;          /* 回调第一个参数              */
};

typedef void (*tcpsniff_pkt_handler)(void *ud, const struct pcap_pkthdr *, const struct ip *, const struct tcphdr *, const u_char *payload, size_t payload_size);
bool tcpsniff(struct tcpsniff_opt *, tcpsniff_pkt_handler);
void tcpsniff_exit();

#endif