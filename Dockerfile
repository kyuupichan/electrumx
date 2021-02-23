FROM python:3.7-alpine3.11

WORKDIR /source

RUN apk add --no-cache \
        git \
        build-base \
        openssl \
        libressl-dev \
        libffi-dev \
        gcc && \
    apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/v3.11/main leveldb-dev && \
    apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing rocksdb-dev && \
    pip install \
        aiohttp \
        pylru \
        plyvel \
        websockets \
        leveldb \
        python-rocksdb \
        pytest-asyncio \
        pytest-cov \
        pycodestyle \
        coveralls \
        flake8 \
    && mkdir /db

RUN ulimit -n 1048576

VOLUME /db

ENV ALLOW_ROOT 1
ENV DB_DIRECTORY /db
ENV DAEMON_URL "http://username:password@hostname:port/"
ENV COIN BitcoinVault
ENV NET mainnet
ENV DB_ENGINE leveldb
ENV HOST ""
ENV SSL_CERTFILE ""
ENV SSL_KEYFILE ""
ENV SERVICES "ssl://:50002,tcp://:50001"
ENV COST_HARD_LIMIT 500000
ENV COST_LIMIT_SOFT 100000
ENV INITIAL_CONCURRENT 500
ENV BANDWIDTH_UNIT_COST 100000
ENV MAX_SEND 10000000
ENV CACHE_MB 2000
ENV MAX_SESSIONS 999999

COPY . .

RUN python3 setup.py install

CMD ["/usr/local/bin/electrumx_server"]
