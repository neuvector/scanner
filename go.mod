module github.com/neuvector/scanner

go 1.14

replace (
	github.com/containerd/containerd => github.com/containerd/containerd v1.3.10
	github.com/containerd/cri => github.com/containerd/cri v1.19.0
	github.com/cri-o/cri-o => github.com/cri-o/cri-o v1.15.4
	github.com/docker/distribution => github.com/docker/distribution v2.8.0-beta.1+incompatible
	github.com/kubernetes/cri-api => k8s.io/cri-api v0.22.3
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc5
	golang.org/x/net => golang.org/x/net v0.0.0-20170421174939-0b588ed7a0cd
	google.golang.org/grpc => google.golang.org/grpc v1.30.1
	k8s.io/api => k8s.io/api v0.18.19
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.18.19
	k8s.io/apimachinery => k8s.io/apimachinery v0.17.17
	k8s.io/apiserver => k8s.io/apiserver v0.18.19
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.18.19
	k8s.io/client-go => k8s.io/client-go v0.18.19
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.18.19
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.18.19
	k8s.io/code-generator => k8s.io/code-generator v0.18.19
	k8s.io/component-base => k8s.io/component-base v0.18.19
	k8s.io/component-helpers => k8s.io/component-helpers v0.20.14
	k8s.io/controller-manager => k8s.io/controller-manager v0.20.14
	k8s.io/cri-api => k8s.io/cri-api v0.18.19
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.18.19
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.18.19
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.18.19
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.18.19
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.18.19
	k8s.io/kubectl => k8s.io/kubectl v0.18.19
	k8s.io/kubelet => k8s.io/kubelet v0.18.19
	k8s.io/kubernetes => k8s.io/kubernetes v1.23.1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.18.19
	k8s.io/metrics => k8s.io/metrics v0.18.19
	k8s.io/mount-utils => k8s.io/mount-utils v0.20.14
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.22.5
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.18.19
)

require (
	github.com/RackSec/srslog v0.0.0-20180709174129-a4725f04ec91 // indirect
	github.com/aws/aws-sdk-go v1.42.36 // indirect
	github.com/codeskyblue/go-sh v0.0.0-20200712050446-30169cf553fe // indirect
	github.com/cri-o/cri-o v0.0.0-00010101000000-000000000000 // indirect
	github.com/docker/docker v20.10.12+incompatible // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/ericchiang/k8s v1.2.0 // indirect
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/google/uuid v1.3.0
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-version v1.4.0 // indirect
	github.com/hashicorp/serf v0.9.7 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/neuvector/neuvector v5.0.0-preview.1.0.20220211045101-73ed561218fc+incompatible
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/streadway/simpleuuid v0.0.0-20130420165545-6617b501e485 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	google.golang.org/grpc v1.40.0
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
)
