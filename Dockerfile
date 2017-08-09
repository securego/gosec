# Docker version must be 17.05 or higher to allow multistage build
# See build and run instructions in README.md

# Builds Gas for utilization
FROM golang:1.8.1-alpine as builder
ENV workspace /go/src/github.com/GoASTScanner/gas
ENV GOPATH /go
COPY . $workspace
WORKDIR $workspace

RUN go vet $(go list ./... | grep -v /vendor/)
RUN CGO_ENABLED=0 go build -o gas .

########################################################

# Runs Gas on all Go files in the current directory when 
# 'docker run' command in README is given
FROM alpine:3.6

COPY --from=builder /go/src/github.com/GoASTScanner/gas/gas /

# Mounted directory should be placed into the workdir
CMD /gas $(find . -path ./vendor -prune -o -type f -name "*.go")
