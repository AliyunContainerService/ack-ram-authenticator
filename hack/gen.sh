#!/usr/bin/env bash

bash ../vendor/k8s.io/code-generator/generate-groups.sh all \
        github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/generated \
        github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/apis \
        "ramauthenticator:v1alpha1" \
        --go-header-file boilerplate.go.txt