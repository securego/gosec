FROM golang:1.10.3-alpine3.8

ENV BIN=gosec

COPY $BIN /go/bin/$BIN
COPY docker-entrypoint.sh /usr/local/bin

ENTRYPOINT ["docker-entrypoint.sh"]
