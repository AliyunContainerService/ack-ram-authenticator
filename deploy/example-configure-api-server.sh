#!/bin/bash

# set up source file path, backup path, kubeconfig file path
# replace with actual path
SOURCE_FILE="kube-apiserver.yaml"
SOURCE_PATH="/etc/kubernetes/manifests"
BACKUP_DIR="$SOURCE_PATH/backups"
KUBECONFIG_PATH="/etc/kubernetes/ack-ram-authenticator/kubeconfig.yaml"
ESCAPE_KUBECONFIG_PATH="\/etc\/kubernetes\/ack-ram-authenticator\/kubeconfig.yaml"
VOLUME_NAME="ack-ram-authenticator"
 
# acquires current time and set backup filename
TIME_NOW=$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_FILENAME="${SOURCE_FILE}.${TIME_NOW}"
 
# backup kube-apiserevr.yaml
mkdir -p $BACKUP_DIR
cp $SOURCE_PATH/$SOURCE_FILE $BACKUP_DIR/$BACKUP_FILENAME

# delete ack-ram-authenticator config
sed -i "/    - --authentication-token-webhook-config-file=/d" $SOURCE_PATH/$SOURCE_FILE
sed -i "/    - mountPath: $ESCAPE_KUBECONFIG_PATH/N;/      name: $VOLUME_NAME/d" $SOURCE_PATH/$SOURCE_FILE
sed -i "/  - hostPath:/N;/      path: $ESCAPE_KUBECONFIG_PATH/N;/      type: FileOrCreate/N;/    name: $VOLUME_NAME/d" $SOURCE_PATH/$SOURCE_FILE

# add ack-ram-authenticator config
sed -i "/    - kube-apiserver/a\    - --authentication-token-webhook-config-file=$KUBECONFIG_PATH" $SOURCE_PATH/$SOURCE_FILE
sed -i "/    volumeMounts:/a\    - mountPath: $KUBECONFIG_PATH\n      name: ack-ram-authenticator" $SOURCE_PATH/$SOURCE_FILE
sed -i "/  volumes:/a\  - hostPath:\n      path: $KUBECONFIG_PATH\n      type: FileOrCreate\n    name: ack-ram-authenticator" $SOURCE_PATH/$SOURCE_FILE