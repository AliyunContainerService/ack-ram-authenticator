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
// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
	v1alpha1 "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/apis/ramauthenticator/v1alpha1"
	scheme "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/generated/clientset/versioned/scheme"
)

// RAMIdentityMappingsGetter has a method to return a RAMIdentityMappingInterface.
// A group's client should implement this interface.
type RAMIdentityMappingsGetter interface {
	RAMIdentityMappings() RAMIdentityMappingInterface
}

// RAMIdentityMappingInterface has methods to work with RAMIdentityMapping resources.
type RAMIdentityMappingInterface interface {
	Create(ctx context.Context, iAMIdentityMapping *v1alpha1.RAMIdentityMapping, opts v1.CreateOptions) (*v1alpha1.RAMIdentityMapping, error)
	Update(ctx context.Context, iAMIdentityMapping *v1alpha1.RAMIdentityMapping, opts v1.UpdateOptions) (*v1alpha1.RAMIdentityMapping, error)
	UpdateStatus(ctx context.Context, iAMIdentityMapping *v1alpha1.RAMIdentityMapping, opts v1.UpdateOptions) (*v1alpha1.RAMIdentityMapping, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.RAMIdentityMapping, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.RAMIdentityMappingList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.RAMIdentityMapping, err error)
	RAMIdentityMappingExpansion
}

// iAMIdentityMappings implements RAMIdentityMappingInterface
type iAMIdentityMappings struct {
	client rest.Interface
}

// newRAMIdentityMappings returns a RAMIdentityMappings
func newRAMIdentityMappings(c *IamauthenticatorV1alpha1Client) *iAMIdentityMappings {
	return &iAMIdentityMappings{
		client: c.RESTClient(),
	}
}

// Get takes name of the iAMIdentityMapping, and returns the corresponding iAMIdentityMapping object, and an error if there is any.
func (c *iAMIdentityMappings) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.RAMIdentityMapping, err error) {
	result = &v1alpha1.RAMIdentityMapping{}
	err = c.client.Get().
		Resource("iamidentitymappings").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of RAMIdentityMappings that match those selectors.
func (c *iAMIdentityMappings) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.RAMIdentityMappingList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.RAMIdentityMappingList{}
	err = c.client.Get().
		Resource("iamidentitymappings").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested iAMIdentityMappings.
func (c *iAMIdentityMappings) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("iamidentitymappings").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a iAMIdentityMapping and creates it.  Returns the server's representation of the iAMIdentityMapping, and an error, if there is any.
func (c *iAMIdentityMappings) Create(ctx context.Context, iAMIdentityMapping *v1alpha1.RAMIdentityMapping, opts v1.CreateOptions) (result *v1alpha1.RAMIdentityMapping, err error) {
	result = &v1alpha1.RAMIdentityMapping{}
	err = c.client.Post().
		Resource("iamidentitymappings").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(iAMIdentityMapping).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a iAMIdentityMapping and updates it. Returns the server's representation of the iAMIdentityMapping, and an error, if there is any.
func (c *iAMIdentityMappings) Update(ctx context.Context, iAMIdentityMapping *v1alpha1.RAMIdentityMapping, opts v1.UpdateOptions) (result *v1alpha1.RAMIdentityMapping, err error) {
	result = &v1alpha1.RAMIdentityMapping{}
	err = c.client.Put().
		Resource("iamidentitymappings").
		Name(iAMIdentityMapping.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(iAMIdentityMapping).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *iAMIdentityMappings) UpdateStatus(ctx context.Context, iAMIdentityMapping *v1alpha1.RAMIdentityMapping, opts v1.UpdateOptions) (result *v1alpha1.RAMIdentityMapping, err error) {
	result = &v1alpha1.RAMIdentityMapping{}
	err = c.client.Put().
		Resource("iamidentitymappings").
		Name(iAMIdentityMapping.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(iAMIdentityMapping).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the iAMIdentityMapping and deletes it. Returns an error if one occurs.
func (c *iAMIdentityMappings) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("iamidentitymappings").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *iAMIdentityMappings) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("iamidentitymappings").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched iAMIdentityMapping.
func (c *iAMIdentityMappings) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.RAMIdentityMapping, err error) {
	result = &v1alpha1.RAMIdentityMapping{}
	err = c.client.Patch(pt).
		Resource("iamidentitymappings").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}