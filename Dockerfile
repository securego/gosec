FROM golang:1.9.4-alpine3.7

ENV BIN=gosec

COPY dist/linux_amd64/$BIN /go/bin/$BIN
COPY docker-entrypoint.sh /usr/local/bin

ENTRYPOINT ["docker-entrypoint.sh"]
