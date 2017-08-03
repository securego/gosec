# Builds the Gas scanner with 'docker build' command, and runs Gas on all Go
# files in your current directory with 'docker run' command.
#
# Docker version must be 17.05 or higher to allow multistage build
#

FROM golang:1.8.1-alpine as builder
ENV workspace /go/src/github.com/GoASTScanner/gas
COPY . $workspace
WORKDIR $workspace

RUN go vet $(go list ./... | grep -v /vendor/)
RUN CGO_ENABLED=0 go build -o gas .

FROM alpine:3.6

LABEL MAINTAINER="David Graves <david.graves@hpe.com>"

COPY --from=builder /go/src/github.com/GoASTScanner/gas/gas /

# Mounted directory should be placed into the workdir
CMD /gas $(find . -path ./vendor -prune -o -type f -name "*.go")
