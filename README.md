OQS-OpenSSL\_1\_0\_2
==================================

**ATTENTION: THIS BRANCH (OQS-OpenSSL\_1\_0\_2) IS NO LONGER MAINTAINED. SEE [DEPRECATION](#deprecation) SECTION BELOW FOR MORE INFORMATION.**

[OpenSSL](https://openssl.org/) is an open-source implementation of the TLS protocol and various cryptographic algorithms ([View the original README](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_0_2-stable/README).)

OQS-OpenSSL\_1\_0\_2 is a fork of OpenSSL 1.0.2 that adds quantum-safe key exchange algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by the OpenSSL project.

- [Overview](#overview)
- [Status](#status)
  * [Limitations and Security](#limitations-and-security)
  * [Supported Key Exchange Methods](#supported-key-exchange-methods)
- [Deprecation](#deprecation)
- [Quickstart](#quickstart)
  * [Building](#building)
    * [Linux and macOS](#linux-and-macOS)
    * [Windows](#windows)
  * [Running](#running)
- [Contributing](#contributing)
- [License](#license)
- [Team](#team)
- [Acknowledgements](#acknowledgements)

## Overview

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms. See [here](https://github.com/open-quantum-safe/liboqs/) for more information.

**OQS-OpenSSL\_1\_0\_2** is a fork that integrates liboqs into OpenSSL 1.0.2.  The goal of this integration is to provide easy prototyping of quantum-safe cryptography in the TLS 1.2 protocol (For TLS 1.3, see the [OQS-OpenSSL\_1\_1\_1](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable) fork. For quantum-safe authentication in TLS 1.2, see the deprecated [OpenSSL\_1\_0\_2-stable](https://github.com/open-quantum-safe/openssl/tree/OpenSSL_1_0_2-stable) branch, which uses an older version of liboqs.)

Both liboqs and this fork are part of the **Open Quantum Safe (OQS) project**, which aims to develop and prototype quantum-safe cryptography. More information about the project can be found [here](https://openquantumsafe.org/).

## Status

This fork is based on the [OpenSSL\_1\_0\_2t tag](https://github.com/openssl/openssl/tree/OpenSSL_1_0_2t), and adds the following:

- quantum-safe key exchange in TLS 1.2
- hybrid (quantum-safe + elliptic curve) key exchange in TLS 1.2
- quantum-safe key exchange primitives from liboqs in OpenSSL's `speed` command

**This fork should be considered experimental**, and has not received the same level of auditing and analysis that OpenSSL has received. See the [Limitations and Security](#limitations-and-security) section below for more information.

**We do not recommend relying on this fork in a production environment or to protect any sensitive data.**

liboqs and our integration into OpenSSL is provided "as is", without warranty of any kind.  See the [LICENSE](https://github.com/open-quantum-safe/liboqs/blob/master/LICENSE.txt) for the full disclaimer.

### Limitations and security

As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms, and strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying quantum-safe cryptography.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this fork, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project.

We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the standardization project.  We strongly recommend such attempts make use of so-called **hybrid cryptography**, in which quantum-safe public-key algorithms are combined with traditional public key algorithms (like RSA or elliptic curves) such that the solution is at least no less secure than existing traditional cryptography. This fork provides the ability to use hybrid cryptography.

Proofs of TLS such as [[JKSS12]](https://eprint.iacr.org/2011/219) and [[KPW13]](https://eprint.iacr.org/2013/339) require a key exchange mechanism that has a form of active security, either in the form of the PRF-ODH assumption, or an IND-CCA KEM.
Some of the KEMs provided in liboqs do provide IND-CCA security; others do not ([these datasheets](https://github.com/open-quantum-safe/liboqs/tree/master/docs/algorithms) specify which provide what security), in which case existing proofs of security of TLS against active attackers do not apply.

### Supported Key Exchange Methods

The following key exchange mechanisms from liboqs are supported:

- `DEFAULT` (see [here](https://github.com/open-quantum-safe/openssl/wiki/Using-liboqs-algorithms-that-are-not-in-the-forks#oqsdefault) for what this denotes)
- `DEFAULT-ECDHE`: `DEFAULT` in hybrid mode with elliptic curve Diffie–Hellman.

For each key exchange method `<KEX>` listed above, the fork makes available the following TLS 1.2 ciphersuites:

- `OQSKEM-<KEX>-RSA-AES128-GCM-SHA256`
- `OQSKEM-<KEX>-ECDSA-AES128-GCM-SHA256`
- `OQSKEM-<KEX>-RSA-AES256-GCM-SHA384`
- `OQSKEM-<KEX>-ECDSA-AES256-GCM-SHA384`

## Deprecation

The OpenSSL project stopped supporting the OpenSSL 1.0.2 series as of January 1, 2020.  As a result, we have decided to discontinue development and support on OQS-OpenSSL 1.0.2.  **This branch is no longer receiving bug fixes, algorithm updates, or any further changes.** Projects relying on post-quantum key exchange in TLS should switch to the OQS-OpenSSL\_1\_1\_1-stable branch.

## Quickstart

The steps below have been confirmed to work on macOS 10.14 (clang 10.0.0), Ubuntu 14.04 (gcc-5), Ubuntu 16.04 (gcc-5), Ubuntu 18.04.1 (gcc-7), and Windows 10 (VS2017 build tools).

### Building

#### Linux and macOS

#### Step 0: Get pre-requisites

For **Ubuntu**, you need to install the following packages:

	sudo apt install autoconf automake gcc libtool libssl-dev make unzip xsltproc

For **macOS**, you need to install the following packages using brew (or a package manager of your choice):

	brew install autoconf automake libtool openssl wget

Then, get the source code of this fork (`<OPENSSL_DIR>` is a directory of your choosing):

	git clone --branch OQS-OpenSSL_1_0_2-stable https://github.com/open-quantum-safe/openssl.git <OPENSSL_DIR>

#### Step 1: Build and install liboqs

The following instructions will download and build liboqs, then install it into a subdirectory inside the OpenSSL folder.  As this branch has been deprecated, its compatibility with changes in liboqs is no longer being maintained.  The build instructions below point to the last release of liboqs known to work with OQS-OpenSSL-1.0.2.

	git clone --branch master https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	git checkout ac03b344679ffec6666376c1d955e1c7e30937e3
	autoreconf -i
	./configure --prefix=<OPENSSL_DIR>/oqs --enable-shared=no --with-sha3=c
	make -j
	make install

Building liboqs requires your system to have (a standard) OpenSSL already installed. `configure` will detect it if it is located in a standard location, such as `/usr` or `/usr/local/opt/openssl` (for brew on macOS).  Otherwise, you may need to specify it with `--with-openssl=<path-to-system-openssl-dir>`.

#### Step 2: Build the fork

In `<OPENSSL_DIR>`, run:

On **Ubuntu**, to use the `OQSKEM-DEFAULT-ECDHE-*` (i.e. hybrid) set of key exchanges listed in the [Supported Key Exchange Methods](#supported-key-exchange-methods) section above, run:

	./Configure no-shared linux-x86_64 -lm

to use the `OQSKEM-DEFAULT-*` (i.e. quantum-safe only) set of key exchanges, run:

	./Configure -DOPENSSL_NO_HYBRID_OQSKEM_ECDHE no-shared linux-x86_64 -lm

Similarly, on **macOS**, to use the `OQSKEM-DEFAULT-ECDHE-*` (i.e. hybrid) set of key exchanges listed in the [Supported Key Exchange Methods](#supported-key-exchange-methods) section above, run:

	./Configure no-shared darwin64-x86_64-cc

to use the `OQSKEM-DEFAULT-*` (i.e. quantum-safe only) set of key exchanges, run:

	./Configure -DOPENSSL_NO_HYBRID_OQSKEM_ECDHE no-shared darwin64-x86_64-cc

Finally:

	make

The fork can also be built with shared libraries, but we have used `no-shared` in the instructions above to avoid having to get the shared libraries in the right place for the runtime linker.

#### Windows

#### Step 0

Make sure you can build the unmodified version of OpenSSL by following the instructions in [INSTALL.W64](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_0_2-stable/INSTALL.W64).

Then, get the fork source code (`<OPENSSL_DIR>` is a directory of your choosing):

	git clone --branch OQS-OpenSSL_1_0_2-stable https://github.com/open-quantum-safe/openssl.git <OPENSSL_DIR>

The above command uses `git`, but alternatively, an archive of the source code can be downloaded and expanded into `<OPENSSL_DIR>`

#### Step 1: Build and install liboqs

Next, you must download and build liboqs using the master branch of liboqs (the nist branch is not currently supported on Windows).  The following instructions will download (using git, alternatively, [download](https://github.com/open-quantum-safe/liboqs/archive/master.zip) and unzip the project) and build liboqs, then copy the required files it into a subdirectory inside the OpenSSL folder.  The liboqs configuration (Debug/Release, x86/x64) must match the one of OpenSSL; the following instructions assume the x64 release configuration is used.  You may need to install dependencies before building liboqs; see the [liboqs master branch README.md](https://github.com/open-quantum-safe/liboqs/blob/master/README.md).

	git clone --branch master https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	git checkout ac03b344679ffec6666376c1d955e1c7e30937e3
	cd ..
	msbuild liboqs\VisualStudio\liboqs.sln /p:Configuration=Release;Platform=x64
	mkdir openssl\oqs
	mkdir openssl\oqs\lib
	mkdir openssl\oqs\include
	xcopy liboqs\VisualStudio\x64\Release\oqs.lib openssl\oqs\lib\
	xcopy /S liboqs\VisualStudio\include openssl\oqs\include\

### Step 3: Build fork of OpenSSL

Now we follow the standard instructions for building OpenSSL:

	perl Configure VC-WIN64A
	ms\do_win64a
	nmake -f ms\nt.mak (or ntdll.mak to build DLLs)

### Running

#### `openssl speed`

OpenSSL's `speed` command performs basic benchmarking of cryptographic primitives.  You can see the results for liboqs primitives by typing:

	apps/openssl speed oqskem

#### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test SSL/TLS connections.

To run a server, you first need to generate a self-signed X.509 certificate:

	apps/openssl req -x509 -new -newkey rsa:2048 -keyout rsa.key -out rsa.crt -nodes -subj "/CN=oqstest" -days 365 -config apps/openssl.cnf

To run a basic TLS server with all OQS ciphersuites enabled:
	apps/openssl s_server -cert rsa.crt -key rsa.key -www -tls1_2 -cipher OQSKEM-DEFAULT

In another terminal window, you can run a TLS client for any or all of the supported ciphersuites, for example:

	apps/openssl s_client -CAfile rsa.crt -cipher OQSKEM-DEFAULT

## License

All modifications to this repository are released under the same terms as OpenSSL, namely as described in the file [LICENSE](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_0_2-stable/LICENSE).

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to OQS-OpenSSL\_1\_0\_2 include:

- Kevin Kane (Microsoft)
- Tancrède Lepoint (SRI)
- Shravan Mishra (University of Waterloo)
- Christian Paquin (Microsoft Research)
- Douglas Stebila (University of Waterloo)

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, Cisco Systems, evolutionQ, and Microsoft Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
