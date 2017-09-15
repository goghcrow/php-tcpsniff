#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "zend.h"
#include "zend_API.h"
#include "SAPI.h"
#include "zend_extensions.h"
#include "zend_exceptions.h"
#include "php_tcpsniff.h"
#include "sniff.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "sniff.h"

typedef struct _usr_pkt_handler {
	zend_fcall_info fci;
	zend_fcall_info_cache fci_cache;
} usr_pkt_handler;

PHP_FUNCTION(tcpsniff);

ZEND_BEGIN_ARG_INFO_EX(arginfo_tcpsniff, 0, 0, 3)
    ZEND_ARG_INFO(0, dev)
    ZEND_ARG_INFO(0, filter)
    ZEND_ARG_CALLABLE_INFO(0, handler, 0)
    ZEND_ARG_ARRAY_INFO(0, option, 1)
ZEND_END_ARG_INFO();

static zend_function_entry tcpsniff_functions[] = {
    PHP_FE(tcpsniff, arginfo_tcpsniff)
    PHP_FE_END
};

zend_module_entry tcpsniff_module_entry = {
     STANDARD_MODULE_HEADER,
    "tcpsniff",
    tcpsniff_functions,           /* Functions */
    PHP_MINIT(tcpsniff),          // MINIT Start of module      PHP_MINIT(fsev)     PHP_MINIT_FUNCTION(fsev){return SUCCESS;}
    NULL,                         // MSHUTDOWN End of module    PHP_MSHUTDOWN(fsev) PHP_MSHUTDOWN_FUNCTION(fsev){return SUCCESS;}
    NULL,                         // RINIT Start of request
    NULL,                         // RSHUTDOWN End of request
    NULL,                         // MINFO phpinfo additions
    PHP_TCPSNIFF_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_TCPSNIFF
ZEND_GET_MODULE(tcpsniff)
#endif


PHP_MINIT_FUNCTION(tcpsniff)
{
    zend_long nlen = strlen(sapi_module.name);
	if (nlen != 3 || memcmp("cli", sapi_module.name, 3) != SUCCESS) {
        zend_error(E_ERROR, "The %s SAPI is not supported by tcpsniff", sapi_module.name);
        return FAILURE;
	}
    
    REGISTER_LONG_CONSTANT("TH_FIN", TH_FIN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("TH_SYN", TH_SYN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("TH_RST", TH_RST, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("TH_PUSH", TH_PUSH, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("TH_ACK", TH_ACK, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("TH_URG", TH_URG, CONST_CS | CONST_PERSISTENT);

	return SUCCESS;        
}

static void pkt_handle(void *ud,
                const struct pcap_pkthdr *pkt_hdr,
                const struct ip *ip_hdr,
                const struct tcphdr *tcp_hdr,
                const u_char *payload, size_t payload_size)
{
    /* static char ip_buf[INET_ADDRSTRLEN]; */

    int result = SUCCESS;
    zval pkt_hdr_z;
    zval ip_hdr_z;
    zval tcp_hdr_z;
    zval payload_z;
    
    array_init(&pkt_hdr_z);
    array_init(&ip_hdr_z);
    array_init(&tcp_hdr_z);
    // 内部 zend_string_init 会做一次copy
    ZVAL_STRINGL(&payload_z, (char*)payload, payload_size);
    
    add_assoc_long(&pkt_hdr_z, "caplen", pkt_hdr->caplen);
    add_assoc_long(&pkt_hdr_z, "len", pkt_hdr->len);
    add_assoc_double(&pkt_hdr_z, "ts", pkt_hdr->ts.tv_sec + pkt_hdr->ts.tv_usec / 1000000.0);
    
    add_assoc_long(&ip_hdr_z, "ip_hl", ip_hdr->ip_hl);
    add_assoc_long(&ip_hdr_z, "ip_v", ip_hdr->ip_v);
    add_assoc_long(&ip_hdr_z, "ip_tos", ip_hdr->ip_tos);
    add_assoc_long(&ip_hdr_z, "ip_len", ntohs(ip_hdr->ip_len));
    add_assoc_long(&ip_hdr_z, "ip_id", ntohs(ip_hdr->ip_id));
    add_assoc_long(&ip_hdr_z, "ip_ttl", ip_hdr->ip_ttl);
    add_assoc_long(&ip_hdr_z, "ip_p", ip_hdr->ip_p);
    add_assoc_long(&ip_hdr_z, "ip_sum", ntohs(ip_hdr->ip_sum));
    add_assoc_long(&ip_hdr_z, "ip_dst", ntohl(ip_hdr->ip_dst.s_addr));
    add_assoc_long(&ip_hdr_z, "ip_src", ntohl(ip_hdr->ip_src.s_addr));
    /*
    inet_ntop(AF_INET, &(ip_hdr->ip_dst.s_addr), ip_buf, INET_ADDRSTRLEN);
    add_assoc_string(&ip_hdr_z, "ip_dst", ip_buf);
    inet_ntop(AF_INET, &(ip_hdr->ip_src.s_addr), ip_buf, INET_ADDRSTRLEN);
    add_assoc_string(&ip_hdr_z, "ip_src", ip_buf);
    */

    add_assoc_long(&tcp_hdr_z, "th_sport", ntohs(tcp_hdr->th_sport));
    add_assoc_long(&tcp_hdr_z, "th_dport", ntohs(tcp_hdr->th_dport));
    add_assoc_long(&tcp_hdr_z, "th_seq", ntohl(tcp_hdr->th_seq));
    add_assoc_long(&tcp_hdr_z, "th_ack", ntohl(tcp_hdr->th_ack));
    add_assoc_long(&tcp_hdr_z, "th_off", tcp_hdr->th_off);
    add_assoc_long(&tcp_hdr_z, "th_flags", tcp_hdr->th_flags);
    add_assoc_long(&tcp_hdr_z, "th_win", ntohs(tcp_hdr->th_win));
    add_assoc_long(&tcp_hdr_z, "th_sum", ntohs(tcp_hdr->th_sum));
    add_assoc_long(&tcp_hdr_z, "th_urp", ntohs(tcp_hdr->th_urp));
    
    zval retval;
    zval args[4];
    args[0] = pkt_hdr_z;
    args[1] = ip_hdr_z;
    args[2] = tcp_hdr_z;
    args[3] = payload_z;
    
    usr_pkt_handler *handler = (usr_pkt_handler *)ud;
    handler->fci.retval = &retval;
	handler->fci.param_count = 4;
    handler->fci.params = args;
    result = zend_call_function(&handler->fci, &handler->fci_cache);
    if (result == SUCCESS) {
        zval_ptr_dtor(&retval);
    } else {
        // 这里有个问题, 用户php代码回调一旦抛出异常, 因为PHP_FUNCTION(tcpsniff)阻塞在poll中, 函数不会返回
        // 又因为php异常机制实现的问题, EG(exception) 已经被标记为true, 但是异常无法抛出
        // 下一次pkt_handle中zend_call_function将会因为EG(exception) == true 返回false

        // 方案1: - 这里使用fatal error 来结束流程, 把异常抛出去 -        
        // php_error_docref(NULL, E_ERROR, "An error occurred while invoking the packet handler function");
        
        // 方案2: 一旦zend_call_function返回false, 终止sniff
        tcpsniff_exit();
        
        /* if (EG(exception)) {
            zend_throw_exception(NULL, "An error occurred while invoking the packet handler function");
        } else {
            php_error_docref(NULL, E_ERROR, "An error occurred while invoking the packet handler function");
        } */
    }

    zval_ptr_dtor(&args[0]);
    zval_ptr_dtor(&args[1]);
    zval_ptr_dtor(&args[2]);
    zval_ptr_dtor(&args[3]);
}

PHP_FUNCTION(tcpsniff)
{
    char *dev = NULL;
    size_t dev_len = 0;
    char *filter = NULL;
    size_t filter_len = 0;
    zval *opt = NULL;

    usr_pkt_handler handler;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssf|z", &dev, &dev_len, &filter, &filter_len, &handler.fci, &handler.fci_cache, &opt) == FAILURE) {
        return;
    }

    char* c_dev = NULL;
    char* c_filter = NULL;

    if (dev_len) {
        c_dev = emalloc(dev_len + 1);
        memcpy(c_dev, dev, dev_len);
        c_dev[dev_len] = '\0';
    } else {
        c_dev = "any";
    }

    if (filter_len) {
        c_filter = emalloc(filter_len + 1);
        memcpy(c_filter, filter, filter_len);
        c_filter[filter_len] = '\0';
    } else {
        c_filter = "tcp";
    }
    
    c_filter = emalloc(filter_len + 1);
    memcpy(c_filter, filter, filter_len);
    c_filter[filter_len] = '\0';

    struct tcpsniff_opt sniff_opt = {
        .snaplen = 65535,
        .pkt_cnt_limit = 0,
        .timeout_limit = 10,
        .device = c_dev,
        .filter_exp = c_filter,
        .ud = &handler
    };

    if (opt && !ZVAL_IS_NULL(opt)) {
        HashTable *ht = Z_ARRVAL_P(opt);
        zval* ht_entry;
        ht_entry = zend_hash_str_find(ht, "snaplen", sizeof("snaplen") - 1);
        if (ht_entry) {
            convert_to_long(ht_entry);
            if (Z_TYPE_P(ht_entry) == IS_LONG && Z_LVAL_P(ht_entry) >= 0) {
                sniff_opt.snaplen = Z_LVAL_P(ht_entry);
            }
        }
        ht_entry = zend_hash_str_find(ht, "pkt_cnt_limit", sizeof("pkt_cnt_limit") - 1);
        if (ht_entry) {
            convert_to_long(ht_entry);
            if (Z_TYPE_P(ht_entry) == IS_LONG && Z_LVAL_P(ht_entry) >= 0) {
                sniff_opt.pkt_cnt_limit = Z_LVAL_P(ht_entry);                
            }
        }
        ht_entry = zend_hash_str_find(ht, "timeout_limit", sizeof("timeout_limit") - 1);
        if (ht_entry) {
            convert_to_long(ht_entry);
            if (Z_TYPE_P(ht_entry) == IS_LONG && Z_LVAL_P(ht_entry) >= 0) {
                sniff_opt.timeout_limit = Z_LVAL_P(ht_entry);
            }
        }
    }

    if (!tcpsniff(&sniff_opt, pkt_handle))
    {
        efree(c_dev);
        efree(c_filter);
        RETURN_FALSE;
    }
    efree(c_dev);
    efree(c_filter);
    RETURN_TRUE;
}