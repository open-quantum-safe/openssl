OQS-OpenSSL3
==================================

[OpenSSL](https://openssl.org/) is an open-source implementation of the TLS protocol and various cryptographic algorithms ([View the original README](https://github.com/openssl/openssl/blob/master/README.md))

OQS-OpenSSL3 is a fork of OpenSSL 3 (alpha/master branch) that adds quantum-safe key exchange and authentication algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by the OpenSSL project.

## Overview 

This implementation utilizes the [OpenSSL Provider concept](https://www.openssl.org/docs/manmaster/man7/provider.html) for this integration. As [KEM providers](https://www.openssl.org/docs/manmaster/man7/provider-kem.html) are fully integrated into OpenSSL3, KEM-based TLS session establishment using algorithms from liboqs is fully supported. As the same level of provider integration is not yet available for signature algorithms, liboqs signature provider support, e.g., for certificate generation or CMS, is not yet available in this branch. Parties interested in such functionality should check out the [primary supported, OQS-OpenSSL1_1_1 branch of the OQS-OpenSSL project](https://github.com/open-quantum-safe/openssl).

## Status

This fork is currently in sync with [OpenSSL master](https://github.com/openssl/openssl), and adds the following:

- quantum-safe key exchange in TLS 1.3 using OpenSSL3 KEM provider interface
- quantum-safe key management using OpenSSL3 provider interface

## Building 

This branch can be built using a standard openssl `Configure` command, e.g., `./Configure --prefix=/opt/ossl3 --openssldir=/opt/ossl3 '-Wl,-rpath,$(LIBRPATH)'`, followed by an equally standard `make install_sw` instruction.

Note that providing an install location (`/opt/ossl3` in this example) is required to permit the resultant openssl binaries and configuration files to be properly picked up. Most notably, the OQS provider library needs to be activated by the `openssl.cnf` file. Proper installation can be verified by running `/opt/ossl3/bin/openssl list -providers`: The OQS provider must be listed if the build succeeded.

Further note that presence of liboqs' libraries and include files in the folder `oqs` [as documented here](https://github.com/open-quantum-safe/openssl#step-1-build-and-install-liboqs) is a prerequisite to a successful build.

Final note: This branch is work in progress; building has only been tested on Linux, a CI integration is not yet done.

## Running

All standard openssl commands can be utilized. In addition, all [KEM algorithms provided by liboqs](https://github.com/open-quantum-safe/openssl#key-exchange) (at this time, without support for hybrid algorithms) can be triggered for session establishment.

Assuming standard creation of RSA server certificates, these commands show proper operation of OQS-based TLS session establishment:

Example server start: `/opt/ossl3/bin/openssl s_server -cert rsa_srv.crt -key rsa_srv.key -www -tls1_3 -groups kyber768:frodo640shake`
Example client start: `/opt/ossl3/bin/openssl s_client -groups frodo640shake`

*Note:* For these demo commands to work, be sure to have all required OpenSSL providers active, at least 'oqsprovider' (for the OQS KEM algorithms) and 'default' (for the RSA certificate) provider. Do this by listing them as active in your `openssl.cnf` (in /opt/ossl3 if using the exact same build parameters as described in this README).

## Third-party integration

As OpenSSL3 has not yet reached beta status, no further application integrations are available.

## License

All modifications to this repository are released under the same terms as OpenSSL, namely as described in the file [LICENSE](LICENSE.txt).

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to OQS-OpenSSL3 include:

- Michael Baentsch 

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
