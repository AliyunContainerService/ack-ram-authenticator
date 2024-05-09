#!/bin/bash

# delete ack-ram-authenticator config
sed -i '/    - --authentication-token-webhook-config-file=\/etc\/kubernetes\/ack-ram-authenticator\/kubeconfig.yaml/d' /etc/kubernetes/manifests/kube-apiserver.yaml
sed -i "/volumeMounts/,+1{/ack-ram-authenticator/{N;d;}};/volumes/,+3{/ack-ram-authenticator/{N;d;}}" /etc/kubernetes/manifests/kube-apiserver.yaml

# add ack-ram-authenticator config
sed -i '/    - kube-apiserver/a\    - --authentication-token-webhook-config-file=/etc/kubernetes/ack-ram-authenticator/kubeconfig.yaml' /etc/kubernetes/manifests/kube-apiserver.yaml
sed -i '/    volumeMounts:/a\    - mountPath: /etc/kubernetes/ack-ram-authenticator/kubeconfig.yaml\n      name: ack-ram-authenticator' /etc/kubernetes/manifests/kube-apiserver.yaml
sed -i '/  volumes:/a\  - hostPath:\n      path: /etc/kubernetes/ack-ram-authenticator/kubeconfig.yaml\n      type: FileOrCreate\n    name: ack-ram-authenticator' /etc/kubernetes/manifests/kube-apiserver.yaml