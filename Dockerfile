FROM golang:1.10.4-alpine3.8

COPY gosec /usr/local/bin

ENTRYPOINT ["gosec"]
