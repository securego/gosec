FROM golang:1.9.4-alpine3.7

ENV BIN=gas

COPY build/*-linux-amd64 /go/bin/$BIN

ENTRYPOINT /go/bin/$BIN

