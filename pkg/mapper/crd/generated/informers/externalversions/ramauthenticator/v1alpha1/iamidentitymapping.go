/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
	ramauthenticatorv1alpha1 "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/apis/ramauthenticator/v1alpha1"
	versioned "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/generated/clientset/versioned"
	internalinterfaces "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/generated/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/generated/listers/ramauthenticator/v1alpha1"
)

// RAMIdentityMappingInformer provides access to a shared informer and lister for
// RAMIdentityMappings.
type RAMIdentityMappingInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.RAMIdentityMappingLister
}

type rAMIdentityMappingInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewRAMIdentityMappingInformer constructs a new informer for RAMIdentityMapping type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewRAMIdentityMappingInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredRAMIdentityMappingInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredRAMIdentityMappingInformer constructs a new informer for RAMIdentityMapping type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredRAMIdentityMappingInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.RamauthenticatorV1alpha1().RAMIdentityMappings().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.RamauthenticatorV1alpha1().RAMIdentityMappings().Watch(context.TODO(), options)
			},
		},
		&ramauthenticatorv1alpha1.RAMIdentityMapping{},
		resyncPeriod,
		indexers,
	)
}

func (f *rAMIdentityMappingInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredRAMIdentityMappingInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *rAMIdentityMappingInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&ramauthenticatorv1alpha1.RAMIdentityMapping{}, f.defaultInformer)
}

func (f *rAMIdentityMappingInformer) Lister() v1alpha1.RAMIdentityMappingLister {
	return v1alpha1.NewRAMIdentityMappingLister(f.Informer().GetIndexer())
}