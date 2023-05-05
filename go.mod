module github.com/AliyunContainerService/ack-ram-authenticator

go 1.16

require (
	github.com/alibabacloud-go/darabonba-openapi v0.1.7
	github.com/alibabacloud-go/sts-20150401 v1.1.0
	github.com/alibabacloud-go/tea v1.1.15
	github.com/aliyun/alibaba-cloud-sdk-go v0.0.0-20190916104532-daf2d24ce8d4
	github.com/aliyun/credentials-go v1.2.4
	github.com/fsnotify/fsnotify v1.4.9
	github.com/gofrs/flock v0.7.0
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/manifoldco/promptui v0.9.0
	github.com/prometheus/client_golang v1.11.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.0
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac
	gopkg.in/ini.v1 v1.56.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.22.1
	k8s.io/apiextensions-apiserver v0.0.0-00010101000000-000000000000
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
	k8s.io/component-base v0.22.1
	k8s.io/sample-controller v0.22.1
	sigs.k8s.io/yaml v1.2.0
)

replace k8s.io/api => k8s.io/api v0.22.0

replace k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.22.0

replace k8s.io/apimachinery => k8s.io/apimachinery v0.23.0-alpha.0

replace k8s.io/apiserver => k8s.io/apiserver v0.22.0

replace k8s.io/cli-runtime => k8s.io/cli-runtime v0.22.0

replace k8s.io/client-go => k8s.io/client-go v0.22.0

replace k8s.io/cloud-provider => k8s.io/cloud-provider v0.22.0

replace k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.22.0

replace k8s.io/code-generator => k8s.io/code-generator v0.22.2-rc.0

replace k8s.io/component-base => k8s.io/component-base v0.22.0

replace k8s.io/component-helpers => k8s.io/component-helpers v0.22.0

replace k8s.io/controller-manager => k8s.io/controller-manager v0.22.0

replace k8s.io/cri-api => k8s.io/cri-api v0.23.0-alpha.0

replace k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.22.0

replace k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.22.0

replace k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.22.0

replace k8s.io/kube-proxy => k8s.io/kube-proxy v0.22.0

replace k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.22.0

replace k8s.io/kubectl => k8s.io/kubectl v0.22.0

replace k8s.io/kubelet => k8s.io/kubelet v0.22.0

replace k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.22.0

replace k8s.io/metrics => k8s.io/metrics v0.22.0

replace k8s.io/mount-utils => k8s.io/mount-utils v0.22.1-rc.0

replace k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.22.0

replace k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.22.0

replace k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.22.0

replace k8s.io/sample-controller => k8s.io/sample-controller v0.22.0
