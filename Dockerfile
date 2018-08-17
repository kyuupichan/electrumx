FROM python:3.7-alpine3.8

RUN apk add --no-cache build-base openssl && \
    apk add --no-cache --repository http://nl.alpinelinux.org/alpine/edge/testing leveldb-dev && \
    pip install aiohttp pylru plyvel

ADD . /electrumx
RUN cd /electrumx && \
    python setup.py install && \
    apk del build-base && \
    rm -rf /tmp/*

VOLUME ["/data"]
ENV HOME /data
ENV ALLOW_ROOT 1
ENV DB_DIRECTORY /data
ENV TCP_PORT=50001
ENV SSL_PORT=50002
ENV SSL_CERTFILE ${DB_DIRECTORY}/electrumx.crt
ENV SSL_KEYFILE ${DB_DIRECTORY}/electrumx.key
ENV RPC_HOST 127.0.0.1
ENV HOST ""
WORKDIR /data

EXPOSE 50001 50002

CMD ["/electrumx/electrumx_server"]
