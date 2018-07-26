FROM golang:1.9.4-alpine3.7

ENV BIN=gosec

COPY build/*-linux-amd64 /go/bin/$BIN
COPY docker-entrypoint.sh /usr/local/bin

ENTRYPOINT ["docker-entrypoint.sh"]
