FROM golang:1.11.5-alpine3.9 as build
WORKDIR /go/src/github.com/securego/gosec
COPY . .
RUN apk add -U git make
RUN go get -u github.com/golang/dep/cmd/dep
RUN make

FROM golang:1.11.5-alpine3.9
RUN apk add -U gcc musl-dev
COPY --from=build /go/src/github.com/securego/gosec/gosec /usr/local/bin/gosec
ENTRYPOINT ["gosec"]
