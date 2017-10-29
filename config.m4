PHP_ARG_ENABLE(tcpsniff, whether to enable tcpsniff support, [--enable-tcpsniff Enable tcpsniff support])

dnl 检测扩展是否启用
if test "$PHP_PCAP" != "no"; then

  AC_MSG_CHECKING([PHP version])

  tmp_version=$PHP_VERSION
  if test -z "$tmp_version"; then
    if test -z "$PHP_CONFIG"; then
      AC_MSG_ERROR([php-config not found])
    fi
    php_version=`$PHP_CONFIG --version 2>/dev/null|head -n 1|sed -e 's#\([0-9]\.[0-9]*\.[0-9]*\)\(.*\)#\1#'`
  else
    php_version=`echo "$tmp_version"|sed -e 's#\([0-9]\.[0-9]*\.[0-9]*\)\(.*\)#\1#'`
  fi

  if test -z "$php_version"; then
    AC_MSG_ERROR([failed to detect PHP version, please report])
  fi

  ac_IFS=$IFS
  IFS="."
  set $php_version
  IFS=$ac_IFS
  tcpsniff_php_version=`expr [$]1 \* 1000000 + [$]2 \* 1000 + [$]3`

  if test "$tcpsniff_php_version" -le "7000000"; then
    AC_MSG_ERROR([You need at least PHP 7.0.0 to be able to use this version of tcpsiniff. PHP $php_version found])
  else
    AC_MSG_RESULT([$php_version, ok])
  fi

  dnl -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

  SEARCH_PATH="/usr/local /usr"
  SEARCH_FOR="/include/pcap.h"

  dnl 优先检查当前目录
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

  dnl -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

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


  CFLAGS="-std=gnu99 -g -Wall -I/usr/include/pcap -lpcap"

  PHP_NEW_EXTENSION(tcpsniff, sniff.c tcpsniff.c, $ext_shared, , $CFLAGS)

  dnl PHP_ADD_BUILD_DIR([$ext_builddir/XXX])
fi
