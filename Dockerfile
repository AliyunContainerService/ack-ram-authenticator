FROM golang:1.16.12 as builder
ENV GOPROXY=https://goproxy.cn,direct
ENV GO111MODULE off
WORKDIR /go/src/github.com/AliyunContainerService/ack-ram-authenticator
COPY . .
RUN make build

FROM alpine:3.11.6
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
WORKDIR /bin

RUN apk update && apk upgrade
RUN apk add --no-cache ca-certificates && \
    update-ca-certificates

COPY --from=builder /go/src/github.com/AliyunContainerService/ack-ram-authenticator/build/bin/ack-ram-authenticator /ack-ram-authenticator
#ADD ./build/bin/ack-ram-authenticator /bin/ack-ram-authenticator

ENTRYPOINT ["/ack-ram-authenticator"]
