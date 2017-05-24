#!/bin/bash -x

# get the OQS fork with picnic
cd vendor
wget https://github.com/christianpaquin/liboqs/archive/add-sig-api-with-picnic.zip
unzip add-sig-api-with-picnic
mv liboqs liboqs_bak
mv liboqs-add-sig-api-with-picnic liboqs
cd liboqs
./download-and-setup-picnic.sh
# build picnic
autoreconf -i
./configure --enable-openssl --enable-picnic
make clean
make

