PHP_ARG_ENABLE(tcpsniff, whether to enable tcpsniff support, [--enable-tcpsniff Enable tcpsniff support])

if test "$PHP_PCAP" != "no"; then
  
  SEARCH_PATH="/usr/local /usr"
  SEARCH_FOR="/include/pcap.h"

  # 优先检查当前目录
  if test -r $PHP_PCAP/$SEARCH_FOR; then
    PCAP_DIR=$PHP_PCAP
  else
    AC_MSG_CHECKING([for pcap files in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        PCAP_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi

  if test -z "$PCAP_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please reinstall the pcap distribution])
  fi

  PHP_ADD_INCLUDE($PCAP_DIR/include)

  LIBNAME=pcap
  LIBSYMBOL=pcap_lib_version

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $PCAP_DIR/lib, PCAP_SHARED_LIBADD)
    AC_DEFINE(HAVE_PCAPLIB,1,[ ])
  ],[
    AC_MSG_ERROR([wrong pcap lib version or lib not found])
  ],[
    -L$PCAP_DIR/lib
  ])
  
  PHP_SUBST(PCAP_SHARED_LIBADD)

  CFLAGS += "-std=gnu99 -g -Wall -I/usr/include/pcap -lpcap"

  PHP_NEW_EXTENSION(tcpsniff, sniff.c tcpsniff.c, $ext_shared)
fi
