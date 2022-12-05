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
// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	v1alpha1 "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/apis/iamauthenticator/v1alpha1"
)

// IAMIdentityMappingLister helps list IAMIdentityMappings.
// All objects returned here must be treated as read-only.
type IAMIdentityMappingLister interface {
	// List lists all IAMIdentityMappings in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.IAMIdentityMapping, err error)
	// Get retrieves the IAMIdentityMapping from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.IAMIdentityMapping, error)
	IAMIdentityMappingListerExpansion
}

// iAMIdentityMappingLister implements the IAMIdentityMappingLister interface.
type iAMIdentityMappingLister struct {
	indexer cache.Indexer
}

// NewIAMIdentityMappingLister returns a new IAMIdentityMappingLister.
func NewIAMIdentityMappingLister(indexer cache.Indexer) IAMIdentityMappingLister {
	return &iAMIdentityMappingLister{indexer: indexer}
}

// List lists all IAMIdentityMappings in the indexer.
func (s *iAMIdentityMappingLister) List(selector labels.Selector) (ret []*v1alpha1.IAMIdentityMapping, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.IAMIdentityMapping))
	})
	return ret, err
}

// Get retrieves the IAMIdentityMapping from the index for a given name.
func (s *iAMIdentityMappingLister) Get(name string) (*v1alpha1.IAMIdentityMapping, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("iamidentitymapping"), name)
	}
	return obj.(*v1alpha1.IAMIdentityMapping), nil
}
