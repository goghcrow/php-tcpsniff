#ifndef UTIL_H
#define UTIL_H

#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/tcp.h> /* struct tcphdr */
#include <stdbool.h>

/* -=-=-=-=-=--=-=-=-=-=--=-=-=-=-=- IPV4 -=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=- */
// #define IPV4_ADDR(a, b, c, d) ((a) | ((b) << 8) | ((c) << 16) | ((uint32_t)(d) << 24))
// 网络字节序/大端序
#define IPV4_ADDR(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

#define IPV4_UNSPECIFIED_ADDR IPV4_ADDR(0, 0, 0, 0)
#define IPV4_LOOPBACK_ADDR IPV4_ADDR(127, 0, 0, 1)
#define IPV4_BROADCAST_ADDR IPV4_ADDR(255, 255, 255, 255)

#define IPV4_IS_BROADCAST_ADDR(ipAddr) ((ipAddr == IPV4_BROADCAST_ADDR))

#define IPV4_MULTICAST_PREFIX IPV4_ADDR(224, 0, 0, 0)
#define IPV4_MULTICAST_MASK IPV4_ADDR(240, 0, 0, 0)
#define IPV4_IS_MULTICAST_ADDR(ipAddr) ((ipAddr & IPV4_MULTICAST_MASK) == IPV4_MULTICAST_PREFIX)

/* -=-=-=-=-=--=-=-=-=-=--=-=-=-=-=- TCP -=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=- */
/*
 *	TCP option
 */
#define TCPOPT_NOP 1       /* Padding */
#define TCPOPT_EOL 0       /* End of options */
#define TCPOPT_MSS 2       /* Segment size negotiating */
#define TCPOPT_WINDOW 3    /* Window scaling */
#define TCPOPT_SACK_PERM 4 /* SACK Permitted */
#define TCPOPT_SACK 5      /* SACK Block */
#define TCPOPT_TIMESTAMP 8 /* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG 19   /* MD5 Signature (RFC2385) */
#define TCPOPT_FASTOPEN 34 /* Fast open (RFC7413) */
#define TCPOPT_EXP 254     /* Experimental */

/*
  * TCP option lengths
  */
#define TCPOLEN_MSS 4
#define TCPOLEN_WINDOW 3
#define TCPOLEN_SACK_PERM 2
#define TCPOLEN_TIMESTAMP 10

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED 12

/*These are used to set the sack_ok field in struct tcp_options_received */
#define TCP_SACK_SEEN (1 << 0)    /*1 = peer is SACK capable, */
#define TCP_FACK_ENABLED (1 << 1) /*1 = FACK is enabled locally*/
#define TCP_DSACK_SEEN (1 << 2)   /*1 = DSACK was received from peer*/

struct tcpopt
{
  uint32_t rcv_tsval;     /* Time stamp value */
  uint32_t rcv_tsecr;     /* Time stamp echo reply */
  uint8_t sack_ok;        /* SACK seen on SYN packet	*/
  uint8_t snd_wscale;     /* Window scaling received from sender	*/
  uint16_t mss_clamp;     /* Maximal mss, negotiated at connection setup */
};

bool tcp_parse_recv_options(const struct tcphdr *th, struct tcpopt *opt);

#endif