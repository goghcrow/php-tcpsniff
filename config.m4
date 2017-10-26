PHP_ARG_ENABLE(tcpsniff, whether to enable tcpsniff support,
[ --enable-tcpsniff           Enable tcpsniff support])

if test "$PHP_TCPSNIFF" != "no"; then
  CFLAGS="-std=gnu99 -g -Wall -lpcap"
  PHP_NEW_EXTENSION(tcpsniff,  util.c sniff.c, $ext_shared)
fi