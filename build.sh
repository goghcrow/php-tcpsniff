phpize --clean
phpize
./configure
make -j2
# make install
# extenion=tcpsniff.so
make clean
phpize --clean