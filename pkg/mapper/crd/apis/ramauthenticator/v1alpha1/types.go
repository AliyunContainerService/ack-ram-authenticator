/*
Copyright 2017 The Kubernetes Authors.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RAMIdentityMapping is a specification for a RAMIdentityMapping resource
type RAMIdentityMapping struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RAMIdentityMappingSpec   `json:"spec"`
	Status RAMIdentityMappingStatus `json:"status"`
}

// RAMIdentityMappingSpec is the spec for a RAMIdentityMapping resource
type RAMIdentityMappingSpec struct {
	ARN      string   `json:"arn"`
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

// RAMIdentityMappingStatus is the status for a RAMIdentityMapping resource
type RAMIdentityMappingStatus struct {
	CanonicalARN string `json:"canonicalARN"`
	UserID       string `json:"userID"`
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RAMIdentityMappingList is a list of RAMIdentityMapping resources
type RAMIdentityMappingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []RAMIdentityMapping `json:"items"`
}
