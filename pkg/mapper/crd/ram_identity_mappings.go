package crd

import (
	"context"
	"fmt"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"reflect"
	"time"
)

const (
	PluralName   = "ramidentitymappings"
	SingularName = "ramidentitymapping"
	GroupName    = "ramauthenticator.k8s.alibabacloud"
	Kind         = "RAMIdentityMapping"
	ListKind     = "RAMIdentityMappingList"
	Version      = "v1alpha1"
	Object       = "object"
	Spec         = "spec"
	Status       = "status"
	Arn          = "arn"
	Groups       = "groups"
	Username     = "username"
	CanonicalARN = "canonicalARN"
	UserID       = "userID"
)

func getRamIdentityMappingCRD() apiext.CustomResourceDefinition {
	return apiext.CustomResourceDefinition{
		ObjectMeta: meta.ObjectMeta{
			Name: fmt.Sprintf("%s.%s", PluralName, GroupName),
		},
		Spec: apiext.CustomResourceDefinitionSpec{
			Scope: apiext.ClusterScoped,
			Names: apiext.CustomResourceDefinitionNames{
				Plural:   PluralName,
				Kind:     Kind,
				Singular: SingularName,
				ListKind: ListKind,
			},
			Group: GroupName,
			Conversion: &apiext.CustomResourceConversion{
				Strategy: apiext.NoneConverter,
			},
			Versions: []apiext.CustomResourceDefinitionVersion{
				{
					Name:    Version,
					Served:  true,
					Storage: true,
					Schema: &apiext.CustomResourceValidation{
						OpenAPIV3Schema: &apiext.JSONSchemaProps{
							Type: Object,
							Properties: map[string]apiext.JSONSchemaProps{
								Spec: {
									Properties: map[string]apiext.JSONSchemaProps{
										Arn: {
											Type: "string",
										},
										Groups: {
											Items: &apiext.JSONSchemaPropsOrArray{
												Schema: &apiext.JSONSchemaProps{
													Type: "string",
												},
											},
											Type: "array",
										},
										Username: {
											Type: "string",
										},
									},
									Required: []string{
										Arn,
										Username,
									},
									Type: Object,
								},
								Status: {
									Properties: map[string]apiext.JSONSchemaProps{
										CanonicalARN: {
											Type: "string",
										},
										UserID: {
											Type: "string",
										},
									},
									Type: Object,
								},
							},
						},
					},
				},
			},
		},
	}
}

func isActivating(crd *apiext.CustomResourceDefinition) bool {
	if crd == nil || reflect.ValueOf(crd).IsNil() || crd.GetName() == "" {
		return false
	}
	return crd.GetDeletionTimestamp().IsZero()
}

func SyncCRD(apiExtClientSet apiextcs.Interface) error {
	ramIdentityMappingCRD := getRamIdentityMappingCRD()
	var crdCli = apiExtClientSet.ApiextensionsV1().CustomResourceDefinitions()
	var crdActual, err = crdCli.Get(context.TODO(), ramIdentityMappingCRD.Name, meta.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	var crdExpected = ramIdentityMappingCRD.DeepCopy()

	if !isActivating(crdActual) {
		// create if not found
		var _, err = crdCli.Create(context.TODO(), crdExpected, meta.CreateOptions{})
		if err == nil {
			return nil
		}
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		// fetch again to confirm
		crdActual, err = crdCli.Get(context.TODO(), ramIdentityMappingCRD.Name, meta.GetOptions{})
		if err != nil {
			return err
		}
	}
	if reflect.DeepEqual(crdExpected.Spec, crdActual.Spec) {
		return nil
	}
	// update if not the same
	crdExpected.ResourceVersion = crdActual.ResourceVersion
	_, err = crdCli.Update(context.TODO(), crdExpected, meta.UpdateOptions{})
	if err != nil {
		return err
	}

	// check status
	var timeCtx, timeCancel = context.WithTimeout(context.Background(), time.Minute)
	defer timeCancel()
	return wait.PollImmediateUntil(5*time.Second, func() (bool, error) {
		var crdActual, err = crdCli.Get(context.TODO(), ramIdentityMappingCRD.Name, meta.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
		var conds = crdActual.Status.Conditions
		for i := range conds {
			if conds[i].Type == apiext.Established && conds[i].Status == apiext.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	}, timeCtx.Done())
}
