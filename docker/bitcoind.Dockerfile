FROM ubuntu:18.04

RUN apt-get update && \
    apt-get -y install --no-install-recommends --no-install-suggests \
    build-essential \
    curl \
    unzip \
    libboost-all-dev \
    libevent-dev \
    libssl-dev \
    libzmq3-dev \
    pkg-config \
    git \
    unzip \
    autoconf \
    automake \
    libtool
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:bitcoin/bitcoin
RUN apt-get update && apt-get -y install libdb4.8-dev libdb4.8++-dev

WORKDIR /source
RUN curl -L -k -f  https://github.com/bitcoinvault/bitcoinvault/archive/master.zip -o bitcoinvault.zip
RUN unzip bitcoinvault.zip
RUN rm bitcoinvault.zip
WORKDIR /source/bitcoinvault-master
RUN env CFLAGS=-O2 CXXFLAGS=-O2 \
    ./autogen.sh
RUN ./configure --disable-bench --disable-tests  --disable-wallet --with-gui=no
RUN make -j`nproc` && make install

RUN mkdir -p /bitcoin

# logrotate
COPY bitcoind-logrotate /etc/logrotate.d/bitcoind
COPY bitcoind-regtest.conf /bitcoin/

ENTRYPOINT ["bvaultd","-conf=/bitcoin/bitcoind-regtest.conf"]


