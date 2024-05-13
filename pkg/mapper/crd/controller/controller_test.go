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
package controller

import (
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/diff"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	ramauthenticator "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/apis/ramauthenticator"
	ramauthenticatorv1alpha1 "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/apis/ramauthenticator/v1alpha1"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/generated/clientset/versioned/fake"
	informers "github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper/crd/generated/informers/externalversions"
)

var (
	alwaysReady        = func() bool { return true }
	noResyncPeriodFunc = func() time.Duration { return 0 }
)

type fixture struct {
	t          *testing.T
	client     *fake.Clientset
	kubeclient *k8sfake.Clientset

	ramIdentityLister []*ramauthenticatorv1alpha1.RAMIdentityMapping

	kubeactions []core.Action
	actions     []core.Action

	objects     []runtime.Object
	kubeobjects []runtime.Object
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{}
	f.t = t
	f.objects = []runtime.Object{}
	f.kubeobjects = []runtime.Object{}
	return f
}

func newRAMIdentityMapping(name, arn, username string) *ramauthenticatorv1alpha1.RAMIdentityMapping {
	return &ramauthenticatorv1alpha1.RAMIdentityMapping{
		TypeMeta: metav1.TypeMeta{APIVersion: ramauthenticatorv1alpha1.SchemeGroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: ramauthenticatorv1alpha1.RAMIdentityMappingSpec{
			ARN:      arn,
			Username: username,
			Groups:   []string{"system:masters"},
		},
	}
}

func (f *fixture) newController() (*Controller, informers.SharedInformerFactory) {
	f.client = fake.NewSimpleClientset(f.objects...)
	f.kubeclient = k8sfake.NewSimpleClientset(f.kubeobjects...)

	i := informers.NewSharedInformerFactory(f.client, noResyncPeriodFunc())

	c := New(f.kubeclient, f.client, i.Ramauthenticator().V1alpha1().RAMIdentityMappings())

	c.ramMappingsSynced = alwaysReady
	c.recorder = &record.FakeRecorder{}

	for _, f := range f.ramIdentityLister {
		i.Ramauthenticator().V1alpha1().RAMIdentityMappings().Informer().GetIndexer().Add(f)
	}

	return c, i
}

func (f *fixture) run(ramIdentityName string) {
	f.runController(ramIdentityName, true, false)
}

func (f *fixture) runExpectError(ramIdentityName string) {
	f.runController(ramIdentityName, true, true)
}

func (f *fixture) runController(ramIdentityName string, startInformers bool, expectError bool) {
	c, i := f.newController()
	if startInformers {
		stopCh := make(chan struct{})
		defer close(stopCh)
		i.Start(stopCh)
	}

	err := c.syncHandler(ramIdentityName)
	if !expectError && err != nil {
		f.t.Errorf("error syncing ram identity %v", err)
	} else if expectError && err == nil {
		f.t.Error("expected error syncing ram identity, got nil")
	}

	actions := filterInformerActions(f.client.Actions())
	for i, action := range actions {
		if len(f.actions) < i+1 {
			f.t.Errorf("%d unexpected actions: %+v", len(actions)-len(f.actions), actions[i:])
			break
		}
		expectedAction := f.actions[i]
		checkAction(expectedAction, action, f.t)
	}

	if len(f.actions) > len(actions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.actions)-len(actions), f.actions[len(actions):])
	}

	k8sActions := filterInformerActions(f.kubeclient.Actions())
	for i, action := range k8sActions {
		if len(f.kubeactions) < i+1 {
			f.t.Errorf("%d unexpected actions: %+v", len(k8sActions)-len(f.kubeactions), k8sActions[i:])
			break
		}

		expectedAction := f.kubeactions[i]
		checkAction(expectedAction, action, f.t)
	}

	if len(f.kubeactions) > len(k8sActions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.kubeactions)-len(k8sActions), f.kubeactions[len(k8sActions):])
	}
}

func checkAction(expected, actual core.Action, t *testing.T) {
	if !(expected.Matches(actual.GetVerb(), actual.GetResource().Resource) && actual.GetSubresource() == expected.GetSubresource()) {
		t.Errorf("expected\n\t%#v\ngot\n\t%#v", expected, actual)
		return
	}

	if reflect.TypeOf(actual) != reflect.TypeOf(expected) {
		t.Errorf("action has wrong type. Expected: %t. Got: %t", expected, actual)
		return
	}

	switch a := actual.(type) {
	case core.CreateAction:
		e, _ := expected.(core.CreateAction)
		expObject := e.GetObject()
		object := a.GetObject()

		if !reflect.DeepEqual(expObject, object) {
			t.Errorf("action %s %s has wrong object\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintDiff(expObject, object))
		}
	case core.UpdateAction:
		e, _ := expected.(core.UpdateAction)
		expObject := e.GetObject()
		object := a.GetObject()

		if !reflect.DeepEqual(expObject, object) {
			t.Errorf("action %s %s has wrong object\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintDiff(expObject, object))
		}
	case core.PatchAction:
		e, _ := expected.(core.PatchAction)
		expPatch := e.GetPatch()
		patch := a.GetPatch()

		if !reflect.DeepEqual(expPatch, patch) {
			t.Errorf("action %s %s has wrong patch\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintDiff(expPatch, patch))
		}
	}
}

func filterInformerActions(actions []core.Action) []core.Action {
	ret := []core.Action{}
	for _, action := range actions {
		if len(action.GetNamespace()) == 0 &&
			(action.Matches("list", "ramidentitymappings") ||
				action.Matches("watch", "ramidentitymappings")) {
			continue
		}
		ret = append(ret, action)
	}

	return ret
}

func (f *fixture) expectUpdateAction(ramidentity *ramauthenticatorv1alpha1.RAMIdentityMapping) {
	action := core.NewRootUpdateAction(schema.GroupVersionResource{Group: ramauthenticator.GroupName, Resource: "ramidentitymappings"}, ramidentity)
	f.actions = append(f.actions, action)
}

func (f *fixture) expectUpdateStatusAction(ramidentity *ramauthenticatorv1alpha1.RAMIdentityMapping) {
	action := core.NewRootUpdateSubresourceAction(schema.GroupVersionResource{Group: ramauthenticator.GroupName, Resource: "ramidentitymappings"}, "status", ramidentity)
	f.actions = append(f.actions, action)
}

func (f *fixture) expectCreateAction(ramidentity *ramauthenticatorv1alpha1.RAMIdentityMapping) {
	action := core.NewRootCreateAction(schema.GroupVersionResource{Group: ramauthenticator.GroupName, Resource: "ramidentitymappings"}, ramidentity)
	f.actions = append(f.actions, action)
}

func getKey(ramidentity *ramauthenticatorv1alpha1.RAMIdentityMapping, t *testing.T) string {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(ramidentity)
	if err != nil {
		t.Errorf("unexpected error getting key for ram identity %v : %v", ramidentity.Name, err)
		return ""
	}
	return key
}

func TestRAMIdentityMappingCreation(t *testing.T) {
	f := newFixture(t)
	ramidentity := newRAMIdentityMapping("test", "acs:ram::XXXXXXXXXXXX:user/AuthorizedUser", "user-1")
	f.ramIdentityLister = append(f.ramIdentityLister, ramidentity)
	f.objects = append(f.objects, ramidentity)

	// Update will always add these parameters
	canonicalizedArn := "acs:ram::xxxxxxxxxxxx:user/authorizeduser"
	ramidentity.Status = ramauthenticatorv1alpha1.RAMIdentityMappingStatus{
		CanonicalARN: canonicalizedArn,
	}

	f.expectUpdateStatusAction(ramidentity)
	f.run(getKey(ramidentity, t))
}
