FROM ubuntu:latest

RUN apt-get update -qq \
    && apt-get install -y build-essential \
                          git \
                          autoconf \
                          automake \
                          libtool \
                          libssl-dev \
                          python3-pytest \
                          python3-nose \
                          python3-rednose \
                          doxygen;

COPY . /root/openssl
WORKDIR /root/openssl/oqs_test
RUN ./scripts/clone_liboqs.sh && \
    ./scripts/build_liboqs.sh && \
    ./scripts/build_openssl.sh;

WORKDIR /root/openssl
CMD ["/bin/bash"]
