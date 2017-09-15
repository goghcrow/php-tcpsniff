#ifndef PHP_TCPSNIFF_H
#define PHP_TCPSNIFF_H


PHP_MINIT_FUNCTION(tcpsniff);

/* 不支持ZTS */
extern zend_module_entry tcpsniff_module_entry;

/* 定义模块全局变量 */
ZEND_BEGIN_MODULE_GLOBALS(tcpsniff)
    zend_bool debug;
ZEND_END_MODULE_GLOBALS(tcpsniff)

#define TG(v) (tcpsniff_globals.v)

PHP_MINIT_FUNCTION(tcpsniff);

#define PHP_TCPSNIFF_MODULE_NAME   "tcpsniff"
#define PHP_TCPSNIFF_BUILD_DATE    __DATE__ " " __TIME__
#define PHP_TCPSNIFF_VERSION       "0.0.1"
#define PHP_TCPSNIFF_AUTHOR        "xiaofeng"

#endif
