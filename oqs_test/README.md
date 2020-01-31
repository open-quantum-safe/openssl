OQS-OpenSSL Integration Testing
===============================

This directory contains scripts for testing the OQS fork of OpenSSL with liboqs, using all supported algorithms. The [README.md file for the OQS-OpenSSL fork](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_0_2-stable/README.md) describes the various key exchange and authentication mechanisms supported.

First make sure you have **installed the dependencies** for the target OS as indicated in the [top-level testing README](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_0_2-stable/README.md).

Testing on Linux and macOS
--------------------------

The scripts have been tested on macOS 10.14, Debian 10 (Buster), Ubuntu 14.04, Ubuntu 16.04, and Ubuntu 18.04.

### Running directly

Run:

	cd oqs_test
	./run.sh

Alternatively, to log the run.sh output while following live, try:

    ./run.sh | tee `date "+%Y%m%d-%Hh%Mm%Ss-openssl.log.txt"`
	
### Running using CircleCI

You can locally run any of the integration tests that CircleCI runs.  First, you need to install CircleCI's local command line interface as indicated in the [installation instructions](https://circleci.com/docs/2.0/local-cli/).  Then:

	circleci local execute --job <jobname>

where `<jobname>` is one of the following:

- `ssl-amd64-buster-liboqs-master-openssl-102`
- `ssl-x86_64-xenial-liboqs-master-openssl-102`
