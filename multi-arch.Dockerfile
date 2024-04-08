# Build the binary
FROM ack-asi-ci-registry.cn-hangzhou.cr.aliyuncs.com/chorus-public/golang:1.19.9-buster as builder
ARG TARGETOS
ARG TARGETARCH
ARG IMAGE_TAG
ARG COMMIT_SHORT

WORKDIR /go/src/github.com/AliyunContainerService/ack-ram-authenticator

COPY . .

# Build
# TARGETPLATFORM
RUN mkdir -p bin/ && make build -B \
    IMAGE_TAG=${IMAGE_TAG} COMMIT_SHORT=${COMMIT_SHORT} COMMIT=${COMMIT_SHORT} && \
    cp bin/ack-ram-authenticator /ack-ram-authenticator

FROM registry.cn-hangzhou.aliyuncs.com/acs/alpine:3.16-base

WORKDIR /

COPY --from=builder /ack-ram-authenticator /

ENTRYPOINT ["/ack-ram-authenticator"]
