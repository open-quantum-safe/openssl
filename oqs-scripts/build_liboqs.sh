#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - OPENSSL_DIR: path to install liboqs, default ${PROJECT_ROOT}/oqs
#  - LIBOQS_LIBTYPE: if 'shared', build a shared library,
#                    if 'noopenssl', build a static library without OpenSSL SHA/AES code.
#                    else, build a static library.
###########

set -exo pipefail

OPENSSL_DIR=${OPENSSL_DIR:-"$(pwd)/oqs"}

cd oqs-test/tmp/liboqs

rm -rf build
mkdir build && cd build

if [ "x${LIBOQS_LIBTYPE}" == "xshared" ]; then
    cmake .. -GNinja -DCMAKE_INSTALL_PREFIX="${OPENSSL_DIR}" -DOQS_BUILD_ONLY_LIB=ON -DBUILD_SHARED_LIBS=ON
elif [ "x${LIBOQS_LIBTYPE}" == "xnoopenssl" ]; then
    cmake .. -GNinja -DCMAKE_INSTALL_PREFIX="${OPENSSL_DIR}" -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF
else
    cmake .. -GNinja -DCMAKE_INSTALL_PREFIX="${OPENSSL_DIR}" -DOQS_BUILD_ONLY_LIB=ON ..
fi
ninja
ninja install
