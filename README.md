## php-tcpsniff

libpcap简易封装, 使用场景：内网ipv4 + tcp包嗅探

注意：自动过滤非ipV4 Packet与非TCP Segment, option["snaplen"] 设置过小, 会抓取不到ip头与tcp头, 从而导致回调不会触发;

### 说明

0. PHP7 only
1. 仅支持NTS-CLI, 其他模式没有应用场景，遂不支持
2. 依赖libpcap-dev

### install

```
sudo yum install -y libpcap-devel.x86_64
# sudo apt-get install libpcap-dev
# brew install libpcap
phpize --clean
phpize
./configure
make
php -dextension=modules/tcpsniff.so --re tcpsniff
```

```
Extension [ <persistent> extension #47 tcpsniff version 0.0.1 ] {

  - Constants [8] {
    Constant [ integer TH_FIN ] { 1 }
    Constant [ integer TH_SYN ] { 2 }
    Constant [ integer TH_RST ] { 4 }
    Constant [ integer TH_PUSH ] { 8 }
    Constant [ integer TH_ACK ] { 16 }
    Constant [ integer TH_URG ] { 32 }
    Constant [ integer TH_ECE ] { 64 }
    Constant [ integer TH_CWR ] { 128 }
  }

  - Functions {
    Function [ <internal:tcpsniff> function tcpsniff ] {

      - Parameters [4] {
        Parameter #0 [ <required> $dev ]
        Parameter #1 [ <required> $filter ]
        Parameter #2 [ <required> callable $handler ]
        Parameter #3 [ <optional> array or NULL $option ]
      }
    }
  }
}
```

IDEHelper

```php
<?php
if (false) {
    define("TH_FIN", 0x01);
    define("TH_SYN", 0x02);
    define("TH_RST", 0x04);
    define("TH_PUSH", 0x08);
    define("TH_ACK", 0x10);
    define("TH_URG", 0x20);
    define("TH_ECE", 0x40);
    define("TH_CWR", 0x80);

    /**
     * @param string $dev
     * @param string $filter
     * @param callable $handler
     * @param array|null $option
     * @return bool
     */
    function tcpsniff(string $dev, string $filter, callable $handler, array $option = null) {}

    /**
     * @param array $pktHdr
     * @param array $ipHdr
     * @param array $tcpHdr
     * @param string $payload
     */
    $handler = function(array $pktHdr, array $ipHdr, array $tcpHdr, array, $tcpOpt, string $payload) {};
}

```

回调参数示例:

```
  $pktHdr = [
    'caplen' => 134,
    'len' => 134,
    'ts' => 1505142888.657902,
  ];
  $ipHdr = [
    'ip_hl' => 5,
    'ip_v' => 4,
    'ip_tos' => 0,
    'ip_len' => 130,
    'ip_id' => 49426,
    'ip_ttl' => 64,
    'ip_p' => 6,
    'ip_sum' => 0,
    'ip_dst' => long2ip('127.0.0.1'),
    'ip_src' => long2ip('127.0.0.1'),
  ];
  $tcpHdr = [
    'th_sport' => 58995,
    'th_dport' => 9999,
    'th_seq' => 2647432116,
    'th_ack' => 3839326982,
    'th_off' => 8,
    'th_flags' => 24,
    'th_win' => 12759,
    'th_sum' => 65142,
    'th_urp' => 0,
  ];
  $tcpOpt = [
    'rcv_tsval' => 1539399480
    'rcv_tsecr' => 0
    'sack_ok' => 1
    'snd_wscale' => 7
    'mss_clamp' => 1414
  ];
  $payload = 'GET / HTTP/1.1
Host: 127.0.0.1:9999
User-Agent: curl/7.43.0
Accept: */*

';

```

Example

```php
<?php

error_reporting(E_ALL);
ini_set("memory_limit", "10M");

$opt = getopt('i:e:');
$dev = $opt['i'] ?? "any";
$exp = $opt['e'] ?? "tcp";

tcpsniff($dev, $exp, function (array $pktHdr, array $ipHdr, array $tcpHdr, array $tcpOpt, $payload) {
    $t = fmt_ts($pktHdr["ts"]);

    $flags = $tcpHdr["th_flags"];
    $seq = $tcpHdr["th_seq"];
    $ack = $tcpHdr["th_ack"];
    
    $ipSrc = long2ip($ipHdr["ip_src"]);
    $ipDst = long2ip($ipHdr["ip_dst"]);
    $src = "{$ipSrc}:{$tcpHdr["th_sport"]}";
    $dst = "{$ipDst}:{$tcpHdr["th_dport"]}";

	$flags = fmt_flags($flags);
	$len = strlen($payload);
    echo "$t $src -> $dst $flags seq $seq, ack $ack, len $len\n";
	/*if ($tcpOpt["snd_wscale"]) {
		print_r($tcpOpt);
	}*/
});

function fmt_flags($flags)
{
	$str = [];
	if ($flags & TH_SYN) {
		$str[] = "SYN";
	}
	if ($flags & TH_ACK) {
		$str[] = "ACK";
	}
	if ($flags & TH_PUSH) {
		$str[] = "PSH";
	}
	if ($flags & TH_FIN) {
		$str[] = "FIN";
	}
	if ($flags & TH_RST) {
		$str[] = "RST";
	}
	return implode(" ", $str);
}

function fmt_ts($ts)
{
    $now = DateTime::createFromFormat("U.u", $ts);
    if ($now === false) { // 无小数点不满足.u格式
        return date("H:i:s", $ts);
    }
    $now->setTimeZone(new DateTimeZone('Asia/Shanghai'));
    return rtrim($now->format("H:i:s.u"), "0");
}
```

output:

```
$ sudo php -dextension=modules/tcpsniff.so tcpsniff.php
19:55:30.2102 107.170.214.240:32202 -> 192.168.0.104:56740 ACK PSH seq 1647539194, ack 3655832949, len 31
19:55:30.2102 192.168.0.104:56740 -> 107.170.214.240:32202 ACK seq 3655832949, ack 1647539225, len 0
19:55:30.2103 127.0.0.1:1080 -> 127.0.0.1:56739 ACK PSH seq 4105645171, ack 1499206056, len 31
19:55:30.2103 127.0.0.1:1080 -> 127.0.0.1:56739 ACK PSH seq 4105645171, ack 1499206056, len 31
19:55:30.2103 127.0.0.1:56739 -> 127.0.0.1:1080 ACK seq 1499206056, ack 4105645202, len 0
19:55:30.2103 127.0.0.1:56739 -> 127.0.0.1:1080 ACK seq 1499206056, ack 4105645202, len 0
19:55:30.2104 127.0.0.1:56739 -> 127.0.0.1:1080 ACK PSH seq 1499206056, ack 4105645202, len 35
19:55:30.2104 127.0.0.1:56739 -> 127.0.0.1:1080 ACK PSH seq 1499206056, ack 4105645202, len 35
19:55:30.2105 127.0.0.1:1080 -> 127.0.0.1:56739 ACK seq 4105645202, ack 1499206091, len 0
19:55:30.2105 127.0.0.1:1080 -> 127.0.0.1:56739 ACK seq 4105645202, ack 1499206091, len 0
19:55:30.2105 192.168.0.104:56740 -> 107.170.214.240:32202 ACK PSH seq 3655832949, ack 1647539225, len 35
19:55:30.4072 107.170.214.240:32202 -> 192.168.0.104:56740 ACK seq 1647539222, ack 3655832949, len 1
19:55:30.4072 192.168.0.104:56740 -> 107.170.214.240:32202 ACK seq 3655832984, ack 1647539225, len 0
19:55:30.6012 107.170.214.240:32202 -> 192.168.0.104:56740 ACK seq 1647539225, ack 3655832984, len 0
19:55:31.1598 107.170.214.240:32202 -> 192.168.0.104:56740 ACK seq 1647539225, ack 3655832984, len 0
19:55:31.9505 192.168.0.104:55198 -> 115.236.39.211:443 ACK PSH seq 1593730746, ack 59146333, len 68
19:55:31.9745 115.236.39.211:443 -> 192.168.0.104:55198 ACK PSH seq 59146333, ack 1593730814, len 40
19:55:31.9745 192.168.0.104:55198 -> 115.236.39.211:443 ACK seq 1593730814, ack 59146373, len 0
19:55:33.6194 192.168.0.104:55151 -> 115.236.39.211:443 ACK PSH seq 2467895306, ack 42360090, len 28
19:55:33.6265 115.236.39.211:443 -> 192.168.0.104:55151 ACK PSH seq 42360090, ack 2467895334, len 60
19:55:33.6266 192.168.0.104:55151 -> 115.236.39.211:443 ACK seq 2467895334, ack 42360150, len 0
19:55:34.2174 223.252.199.66:80 -> 192.168.0.104:56791 ACK FIN seq 2030706024, ack 1135276389, len 0
```

### 参考


```c
#include <pcap/pcap.h>

/* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
struct pcap_pkthdr
{
    struct timeval ts;      /* Timestamp of capture             */
    bpf_u_int32 caplen;     /* Number of bytes that were stored */
    bpf_u_int32 len;        /* Total length of the packet       */
};


```c
#include <net/ethernet.h>

struct  ether_header {
        u_char  ether_dhost[6];     /* dst MAC   */
        u_char  ether_shost[6];     /* src MAC   */
        u_short ether_type;         /* IP ARP ...*/
};
```

```c
struct  ether_arp {
        struct  arphdr ea_hdr;          /* fixed-size header       */
        u_char  arp_sha[6];             /* sender hardware address */
        u_char  arp_spa[4];             /* sender protocol address */
        u_char  arp_tha[6];             /* target hardware address */
        u_char  arp_tpa[4];             /* target protocol address */
};
```

netinet/ip.h

http://unix.superglobalmegacorp.com/BSD4.4/newsrc/netinet/ip.h.html

```c
#define IP_MAXPACKET    65535

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
        u_char  ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
        u_char  ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
        u_char  ip_tos;                 /* type of service */
        short   ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        short   ip_off;                 /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
```

netinet/tcp.h

http://unix.superglobalmegacorp.com/BSD4.4/newsrc/netinet/tcp.h.html

```c

typedef u_long  tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN 
        u_char  th_x2:4,                /* (unused) */
                th_off:4;               /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
        u_char  th_off:4,               /* data offset */
                th_x2:4;                /* (unused) */
#endif
        u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

```

http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/linux_2ip_8h-source.html

```c
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8    tos;
        __u16   tot_len;            /* 偏移四字节为ippkt长度 */
        __u16   id;
        __u16   frag_off;
        __u8    ttl;
        __u8    protocol;
        __u16   check;
        __u32   saddr;
        __u32   daddr;
        /* The options start here. */
};
```

http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/linux_2tcp_8h-source.html

```c
struct tcphdr {
        __u16   source;
        __u16   dest;
        __u32   seq;
        __u32   ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u16   res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u16   doff:4,
                res1:4,
                cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif  
        __u16   window;
        __u16   check;
        __u16   urg_ptr;
};
```

libpcap/sll.h

```c
/*
 * For captures on Linux cooked sockets, we construct a fake header
 * that includes:
 *
 *      a 2-byte "packet type" which is one of:
 *
 *              LINUX_SLL_HOST          packet was sent to us
 *              LINUX_SLL_BROADCAST     packet was broadcast
 *              LINUX_SLL_MULTICAST     packet was multicast
 *              LINUX_SLL_OTHERHOST     packet was sent to somebody else
 *              LINUX_SLL_OUTGOING      packet was sent *by* us;
 *
 *      a 2-byte Ethernet protocol field;
 *
 *      a 2-byte link-layer type;
 *
 *      a 2-byte link-layer address length;
 *
 *      an 8-byte source link-layer address, whose actual length is
 *      specified by the previous value.
 *
 * All fields except for the link-layer address are in network byte order.
 *
 * DO NOT change the layout of this structure, or change any of the
 * LINUX_SLL_ values below.  If you must change the link-layer header
 * for a "cooked" Linux capture, introduce a new DLT_ type (ask
 * "tcpdump-workers@tcpdump.org" for one, so that you don't give it a
 * value that collides with a value already being used), and use the
 * new header in captures of that type, so that programs that can
 * handle DLT_LINUX_SLL captures will continue to handle them correctly
 * without any change, and so that capture files with different headers
 * can be told apart and programs that read them can dissect the
 * packets in them.
 */

/*
 * A DLT_LINUX_SLL fake link-layer header.
 */
#define SLL_HDR_LEN     16              /* total header length */
#define SLL_ADDRLEN     8               /* length of address field */

struct sll_header {
        u_int16_t sll_pkttype;          /* packet type */
        u_int16_t sll_hatype;           /* link-layer address type */
        u_int16_t sll_halen;            /* link-layer address length */
        u_int8_t sll_addr[SLL_ADDRLEN]; /* link-layer address */
        u_int16_t sll_protocol;         /* protocol */
};

/*
 * The LINUX_SLL_ values for "sll_pkttype"; these correspond to the
 * PACKET_ values on Linux, but are defined here so that they're
 * available even on systems other than Linux, and so that they
 * don't change even if the PACKET_ values change.
 */
#define LINUX_SLL_HOST          0
#define LINUX_SLL_BROADCAST     1
#define LINUX_SLL_MULTICAST     2
#define LINUX_SLL_OTHERHOST     3
#define LINUX_SLL_OUTGOING      4


struct tcpopt
{
  uint32_t rcv_tsval;     /* Time stamp value */
  uint32_t rcv_tsecr;     /* Time stamp echo reply */
  uint8_t sack_ok;        /* SACK seen on SYN packet	*/
  uint8_t snd_wscale;     /* Window scaling received from sender	*/
  uint16_t mss_clamp;     /* Maximal mss, negotiated at connection setup */
};
```