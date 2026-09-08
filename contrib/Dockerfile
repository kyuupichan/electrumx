# example of Dockerfile that builds electrumx from the source tree
# ENV variables can be overrided on the `docker run` command

FROM ubuntu:22.04

WORKDIR /
COPY . /electrumx

RUN apt-get update && \
        apt-get -y install python3-pip libgflags-dev zlib1g-dev libzstd-dev \
            librocksdb-dev libleveldb-dev libsnappy-dev libbz2-dev libz-dev liblz4-dev && \
        pip3 install --no-cache-dir Cython==0.29.37 && \
        pip3 install --no-cache-dir python-rocksdb && \
        pip3 install --no-cache-dir -r /electrumx/requirements.txt && \
        pip3 install --no-cache-dir --no-deps /electrumx

ENV SERVICES="tcp://:50001"
ENV COIN=BitcoinSV
ENV DB_DIRECTORY=/db
ENV DAEMON_URL="http://username:password@hostname:port/"
ENV ALLOW_ROOT=true
ENV DB_ENGINE=rocksdb
ENV MAX_SEND=10000000
ENV BANDWIDTH_UNIT_COST=50000
ENV CACHE_MB=2000

VOLUME /db

RUN mkdir -p "$DB_DIRECTORY"

CMD ["/usr/bin/python3", "/usr/local/bin/electrumx_server"]

# build it from the repository root with eg.:
# `docker build -f contrib/Dockerfile -t electrumx .`
# run it with eg.:
# `docker run -d --net=host -v /home/electrumx/db/:/db -e DAEMON_URL="http://youruser:yourpass@localhost:8332" -e REPORT_SERVICES=tcp://example.com:50001 electrumx`
# for a proper clean shutdown, send TERM signal to the running container eg.: `docker kill --signal="TERM" CONTAINER_ID`
