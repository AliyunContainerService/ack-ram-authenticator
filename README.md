# ACK RAM Authenticator for Kubernetes

A tool to use AlibabaCloud RAM credentials to authenticate to a Kubernetes cluster.

## Why do I want this?
If you are an administrator running a Kubernetes cluster on AlibabaCloud, you already need to manage AlibabaCloud RAM credentials to provision and update the cluster.
By using AlibabaCloud RAM Authenticator for Kubernetes, you avoid having to manage a separate credential for Kubernetes access.

If you are building a Kubernetes installer on AlibabaCloud, AlibabaCloud RAM Authenticator for Kubernetes can simplify your bootstrap process.
You won't need to somehow smuggle your initial admin credential securely out of your newly installed cluster.
Instead, you can create a dedicated `KubernetesAdmin` role at cluster provisioning time and set up Authenticator to allow cluster administrator logins.

## How do I use it?
Assuming you have a cluster running in AlibabaCloud and you want to add AlibabaCloud RAM Authenticator for Kubernetes support, you need to:
 1. Create an RAM role or user you'll use to identify users.
 2. Create an CRD in your cluster to store the mapping between RAM roles and Kubernetes users.
 3. Configure the mapping relationship between RAM identities and RBAC permissions.
 4. Run the Authenticator server as a DaemonSet.
 5. Configure your API server to talk to Authenticator.
 6. Set up kubectl to use Authenticator tokens.

### 1. Create an RAM role
First, you must create one or more RAM roles that will be mapped to users/groups inside your Kubernetes cluster.
The easiest way to do this is to log into the RAM Console:
 - Choose the "RAM Roles" / "Create RAM Role" option.
 - Select type of trusted entity "Alibaba Cloud Account", Select Trusted Alibaba Cloud Account "Current Alibaba Cloud Account".
 - Type in a name at "RAM Role Name" and click "OK"

This will create an RAM role with no permissions that can be assumed by authorized users/roles in your account.
Note the AlibabaCloud Resource Name (ARN) of your role, which you will need below.

You can also skip this step and use:
 - An existing role (such as a cross-account access role).
 - An RAM user (see `mapUsers` below).

### 2. Create an CRD
The Authenticator server uses a custom resource definition (CRD) to store the mapping between RAM roles and Kubernetes users.

You can create this CRD with `kubectl apply -f deloy/ramidentitymapping.yaml`, ramidentitymapping.yaml see [`ramidentitymapping.yaml`](deploy/ramidentitymapping.yaml).

### 3. Configure the mapping relationship between RAM identities and RBAC permissions
You need to configure the mapping relationship between RAM identities and RBAC permissions.
First you need to create a RAM identity mapping with `kubectl apply -f deploy/example-ramidentitymapping.yaml`, example-ramidentitymapping.yaml see [`example-ramidentitymapping.yaml`](deploy/example-ramidentitymapping.yaml).
Then you need to configure the mapping relationship between RAM identities and RBAC permissions with `kubectl apply -f deploy/example-binding.yaml`, example-binding.yaml see [`example-binding.yaml`](deploy/example-binding.yaml).

### 4. Run the server
The server is meant to run on each of your master nodes as a DaemonSet with host networking so it can expose a localhost port.

For a sample ConfigMap and DaemonSet configuration, see [`example.yaml`](deploy/example.yaml).
You can run the server with `kubectl apply -f example.yaml`.

#### (Optional) Pre-generate a certificate, key, and kubeconfig
If you're building an automated installer, you can also pre-generate the certificate, key, and webhook kubeconfig files easily using `ack-ram-authenticator init`.
This command will generate files and place them in the configured output directories.

You can run this on each master node prior to starting the API server.
You could also generate them before provisioning master nodes and install them in the appropriate host paths.

If you do not pre-generate files, `ack-ram-authenticator server` will generate them on demand.
This works but requires that you restart your Kubernetes API server after installation , you can run `sh example-configure-api-server.sh`, it will automatically complete the above work and rebuild the kube-apiserver, example-configure-api-server.sh see [`example-configure-api-server.sh`](deploy/example-configure-api-server.sh).

### 5. Configure your API server to talk to the server
The Kubernetes API integrates with ACK RAM Authenticator for Kubernetes using a [token authentication webhook](https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication).
When you run `ack-ram-authenticator server`, it will generate a webhook configuration file and save it onto the host filesystem.
You'll need to add a single additional flag to your API server configuration:
```
--authentication-token-webhook-config-file=/etc/kubernetes/ack-ram-authenticator/kubeconfig.yaml
```

On many clusters, the API server runs as a static pod.
You can add the flag to `/etc/kubernetes/manifests/kube-apiserver.yaml`.
Make sure the host directory `/etc/kubernetes/ack-ram-authenticator/` is mounted into your API server pod.
You can run  `sh example-configure-api-server.sh` to automatically complete the above work.
Note: When you restart the ack-ram-authenticator service, you need run  `sh example-configure-api-server.sh`.
You may also need to restart the kubelet daemon on your master node to pick up the updated static pod definition:
```
systemctl restart kubelet.service
```

### 6. Set up kubectl to use authentication tokens provided by ACK RAM Authenticator for Kubernetes

> This requires a 1.10+ `kubectl` binary to work. If you receive `Please enter Username:` when trying to use `kubectl` you need to update to the latest `kubectl`

Finally, once the server is set up you'll want to authenticate!
You will still need a `kubeconfig` that has the public data about your cluster (cluster CA certificate, endpoint address).
The `users` section of your configuration, however, should include an exec section ([refer to the v1.10 docs](https://kubernetes.io/docs/admin/authentication/#client-go-credential-plugins))::
```yaml
# [...]
users:
    - name: "<your-user-name>"
      user:
        exec:
            command: ack-ram-tool
            args:
                - credential-plugin
                - get-token
                - --cluster-id
                - <your-cluster-id>
                - --api-version
                - v1beta1
                - --log-level
                - error
            apiVersion: client.authentication.k8s.io/v1beta1
            provideClusterInfo: false
            interactiveMode: Never
preferences: {}
```

This means the `kubeconfig` is entirely public data and can be shared across all Authenticator users.
It may make sense to upload it to a trusted public location such as AlibabaCloud OSS.

Make sure you have the `ack-ram-tool` binary installed.
You can install and configure it with [ack-ram-tool](https://aliyuncontainerservice.github.io/ack-ram-tool/).

To authenticate, run `kubectl --kubeconfig /path/to/kubeconfig" [...]`.
kubectl will `exec` the `ack-ram-tool` binary with the supplied params in your kubeconfig which will generate a token and pass it to the apiserver.

## How does it work?
It works using the RAM [`sts:GetCallerIdentity`](https://help.aliyun.com/document_detail/43767.html) API endpoint.
This endpoint returns information about whatever RAM credentials you use to connect to it.

#### Client side (`ack-ram-authenticator token`)
We use this API in a somewhat unusual way by having the Authenticator client generate and pre-sign a request to the endpoint.
We serialize that request into a token that can pass through the Kubernetes authentication system.

#### Server side (`ack-ram-authenticator server`)
The token is passed through the Kubernetes API server and into the Authenticator server's `/authenticate` endpoint via a webhook configuration.
The Authenticator server validates all the parameters of the pre-signed request to make sure nothing looks funny.
It then submits the request to the real `https://sts.aliyuncs.com` server, which validates the client's HMAC signature and returns information about the user.
Now that the server knows the RAM identity of the client, it translates this identity into a Kubernetes user and groups via a simple static mapping.

## What is a cluster ID?
The Authenticator cluster ID is a unique-per-cluster identifier that prevents certain replay attacks.
Specifically, it prevents one Authenticator server (e.g., in a dev environment) from using a client's token to authenticate to another Authenticator server in another cluster.

The cluster ID does need to be unique per-cluster, but it doesn't need to be a secret.
Some good choices are:
 - A random ID such as from `openssl rand 16 -hex`
 - The domain name of your Kubernetes API server

## Specifying Credentials
Credentials can be specified for use with `ack-ram-authenticator` via create file at ~/.acs/credentials, for example:
```
{
  "AcsAccessKeyId": "xxxxxxx",
  "AcsAccessKeySecret": "xxxxxxxxxxxxxxxx"
}
```
if you are using a STS Token, the ~/.acs/credentials file will be like:
```
{
  "AcsAccessKeyId": "xxxxxx",
  "AcsAccessKeySecret": "xxxxxx",
  "AcsAccessSecurityToken": "xxxxxx"
}

```
This includes specifying RAM credentials by utilizing a credentials file.


To use ack-ram-authenticator as client, your kubeconfig would be like this:

```yaml
apiVersion: v1
clusters:
- cluster:
    server: ${server}
    certificate-authority-data: ${cert}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: ack
  name: ack
current-context: ack
kind: Config
preferences: {}
users:
- name: ack
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: ack-ram-authenticator
      args:
        - "token"
        - "-i"
        - "mycluster"
```

## Troubleshooting

If that fails, there are a few possible problems to check for:

 - Make sure your base RAM credentials are available in your shell.

 - Make sure the target role allows your source account access (in the role trust policy).

 - Make sure your source principal (user/role/group) has an RAM policy that allows `sts:AssumeRole` for the target role.

 - Make sure you don't have any explicit deny policies attached to your user, group  that would prevent the `sts:AssumeRole`.

## Full Configuration Format
The client and server have the same configuration format.
They can share the same exact configuration file, since there are no secrets stored in the configuration.

```yaml
# a unique-per-cluster identifier to prevent replay attacks (see above)
clusterID: my-dev-cluster.example.com

# default RAM role to assume for `ack-ram-authenticator token`
defaultRole: acs:ram::000000000000:role/KubernetesAdmin

# server listener configuration
server:
  # localhost port where the server will serve the /authenticate endpoint
  port: 21362 # (default)

  # state directory for generated TLS certificate and private keys
  stateDir: /var/ack-ram-authenticator # (default)

  # output `path` where a generated webhook kubeconfig will be stored.
  generateKubeconfig: /etc/kubernetes/ack-ram-authenticator.kubeconfig # (default)

  # each mapRoles entry maps an RAM role to a username and set of groups
  # Each username and group can optionally contain template parameters:
  #  1) "{{AccountID}}" is the 16 digit ID.
  #  2) "{{SessionName}}" is the role session name.
  mapRoles:
  # statically map acs:ram::000000000000:role/KubernetesAdmin to cluster admin
  - roleARN: acs:ram::000000000000:role/KubernetesAdmin
    username: kubernetes-admin
    groups:
    - system:masters

  # each mapUsers entry maps an RAM role to a static username and set of groups
  mapUsers:
  # map user RAM user Alice in 000000000000 to user "alice" in group "system:masters"
  - userARN: acs:ram::000000000000:user/Alice
    username: alice
    groups:
    - system:masters
```

## Community, discussion, contribution, and support

You are welcome to make new issues and pull reuqests.
