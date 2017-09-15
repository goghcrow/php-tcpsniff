PHP_ARG_ENABLE(tcpsniff, whether to enable tcpsniff support,
[  --enable-tcpsniff           Enable tcpsniff support])

if test "$PHP_TCPSNIFF" != "no"; then
  PHP_NEW_EXTENSION(tcpsniff, 
  	sniff.c,
  $ext_shared)

  CFLAGS="-std=gnu99 -g -Wall -lpcap"
  PHP_NEW_EXTENSION(tcpsniff, tcpsniff.c, $ext_shared)
fi