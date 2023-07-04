package crd

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper"
	ramauthenticatorv1alpha1 "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/apis/ramauthenticator/v1alpha1"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/controller"
	clientset "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/generated/clientset/versioned"
	informers "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/generated/informers/externalversions"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type CRDMapper struct {
	*controller.Controller
	// ramInformerFactory is an informer factory that must be Started
	ramInformerFactory informers.SharedInformerFactory
	// ramMappingsSynced is a function to get if the informers have synced
	ramMappingsSynced cache.InformerSynced
	// ramMappingsIndex is a custom indexer which allows for indexing on canonical arns
	ramMappingsIndex cache.Indexer
}

var _ mapper.Mapper = &CRDMapper{}

func NewCRDMapper(cfg config.Config) (*CRDMapper, error) {
	var err error
	var k8sconfig *rest.Config
	var kubeClient kubernetes.Interface
	var ramClient clientset.Interface
	var ramInformerFactory informers.SharedInformerFactory

	if cfg.Master != "" || cfg.Kubeconfig != "" {
		k8sconfig, err = clientcmd.BuildConfigFromFlags(cfg.Master, cfg.Kubeconfig)
	} else {
		k8sconfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("can't create kubernetes config: %v", err)
	}

	kubeClient, err = kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		return nil, fmt.Errorf("can't create kubernetes client: %v", err)
	}

	ramClient, err = clientset.NewForConfig(k8sconfig)
	if err != nil {
		return nil, fmt.Errorf("can't create authenticator client: %v", err)
	}

	ramInformerFactory = informers.NewSharedInformerFactory(ramClient, time.Second*36000)

	ramMappingInformer := ramInformerFactory.Ramauthenticator().V1alpha1().RAMIdentityMappings()
	ramMappingsSynced := ramMappingInformer.Informer().HasSynced
	ramMappingsIndex := ramMappingInformer.Informer().GetIndexer()

	ctrl := controller.New(kubeClient, ramClient, ramMappingInformer)

	return &CRDMapper{ctrl, ramInformerFactory, ramMappingsSynced, ramMappingsIndex}, nil
}

func NewCRDMapperWithIndexer(ramMappingsIndex cache.Indexer) *CRDMapper {
	return &CRDMapper{ramMappingsIndex: ramMappingsIndex}
}

func (m *CRDMapper) Name() string {
	return mapper.ModeCRD
}

func (m *CRDMapper) Start(stopCh <-chan struct{}) error {
	m.ramInformerFactory.Start(stopCh)
	go func() {
		// Run starts worker goroutines and blocks
		if err := m.Controller.Run(2, stopCh); err != nil {
			panic(err)
		}
	}()

	return nil
}

func (m *CRDMapper) Map(canonicalARN string) (*config.IdentityMapping, error) {
	canonicalARN = strings.ToLower(canonicalARN)
	// support regex matching in ramidentity definition
	if strings.Contains(canonicalARN, "*") {
		logrus.Infof("request canonicalARN %s contains wildcard char", canonicalARN)
		//TODO this is list in cache store, not sure about the permformance
		ramIdentityList, err := m.ramInformerFactory.Ramauthenticator().V1alpha1().RAMIdentityMappings().Lister().List(labels.Everything())
		if err != nil {
			logrus.Errorf("failed to list ramidentity in cluster, err %v", err)
			return nil, mapper.ErrNotMapped
		}
		for _, ri := range ramIdentityList {
			matched, err := regexp.MatchString(ri.Status.CanonicalARN, canonicalARN)
			if err != nil {
				logrus.Errorf("check canonicalARN with pattern %s failed, error: %v", err)
				return nil, mapper.ErrNotMapped
			}
			if matched {
				logrus.Infof("found matching identity %v", ri)
				return &config.IdentityMapping{
					IdentityARN: canonicalARN,
					Username:    ri.Spec.Username,
					Groups:      ri.Spec.Groups,
				}, nil
			}
		}
	}

	var ramidentity *ramauthenticatorv1alpha1.RAMIdentityMapping
	var ok bool
	objects, err := m.ramMappingsIndex.ByIndex("canonicalARN", canonicalARN)
	if err != nil {
		return nil, err
	}

	if len(objects) > 0 {
		for _, obj := range objects {
			ramidentity, ok = obj.(*ramauthenticatorv1alpha1.RAMIdentityMapping)
			if ok {
				break
			}
		}

		if ramidentity != nil {
			return &config.IdentityMapping{
				IdentityARN: canonicalARN,
				Username:    ramidentity.Spec.Username,
				Groups:      ramidentity.Spec.Groups,
			}, nil
		}
	}

	return nil, mapper.ErrNotMapped
}

func (m *CRDMapper) IsAccountAllowed(accountID string) bool {
	return false
}
