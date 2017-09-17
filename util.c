#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/tcp.h> /* struct tcphdr */
#include <stdbool.h>
#include <stdint.h>
#include "util.h"

static inline uint16_t get_unaligned_be16(const uint8_t *p)
{
    return p[0] << 8 | p[1];
}

static inline uint32_t get_unaligned_be32(const uint8_t *p)
{
    return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline bool tcp_parse_aligned_timestamp(struct tcpopt *opt, const struct tcphdr *th)
{
    const uint32_t *ptr = (const uint32_t *)(th + 1);

    if (*ptr == htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP))
    {
        ++ptr;
        opt->rcv_tsval = ntohl(*ptr);
        ++ptr;
        if (*ptr)
        {
            opt->rcv_tsecr = ntohl(*ptr)/* - tp->tsoffset*/;
        }
        else
        {
            opt->rcv_tsecr = 0;
        }
        return true;
    }
    return false;
}

/* 
 * 忽略连接是否建立检测
 * 忽略tcp flags检查, 正常情况若干tcp选项只作用于SYN与SYNACK包
 * 忽略读取选项值的合法性检测
 */
bool tcp_parse_recv_options(const struct tcphdr *th, struct tcpopt *opt)
{
    int th_off = th->th_off;
    // tcp hdr的offset要*4才是真实大小
    if (th_off == (sizeof(*th) / 4))
    {
        return false;
    }
    // 尝试直接比较offset值是否为ts
    else if (th_off == ((sizeof(*th) + TCPOLEN_TSTAMP_ALIGNED) / 4))
    {
        if (tcp_parse_aligned_timestamp(opt, th)) {
            return true;            
        }
    }

    // opt 长度 0 ~ 40
    int length = (th_off * 4) - sizeof(struct tcphdr);
    const unsigned char *ptr = (const unsigned char *)(th + 1);

    while (length > 0)
    {
        int opcode = *ptr++;
        int opsize;

        switch (opcode)
        {
        case TCPOPT_EOL:
            return true;
        case TCPOPT_NOP: /* Ref: RFC 793 section 3.1 */
            length--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2) /* "silly options" */
                return false;
            if (opsize > length)
                return false; /* don't parse partial options */
            switch (opcode)
            {
            case TCPOPT_MSS:
                if (opsize == TCPOLEN_MSS)
                {
                    opt->mss_clamp = get_unaligned_be16(ptr);
                }
                break;
            case TCPOPT_WINDOW:
                if (opsize == TCPOLEN_WINDOW)
                {
                    opt->snd_wscale = *(uint8_t *)ptr;
                }
                break;
            case TCPOPT_TIMESTAMP:
                if (opsize == TCPOLEN_TIMESTAMP)
                {
                    opt->rcv_tsval = get_unaligned_be32(ptr);
                    opt->rcv_tsecr = get_unaligned_be32(ptr + 4);
                }
                break;

            // ignore
            case TCPOPT_SACK_PERM:
                if (opsize == TCPOLEN_SACK_PERM) {
                    opt->sack_ok = TCP_SACK_SEEN;                    
                }
                break;
            case TCPOPT_SACK:
                break;
            case TCPOPT_MD5SIG:
                break;
            case TCPOPT_FASTOPEN:
                break;
            case TCPOPT_EXP:
                break;
            }
            ptr += opsize - 2;
            length -= opsize;
        }
    }

    return true;
}