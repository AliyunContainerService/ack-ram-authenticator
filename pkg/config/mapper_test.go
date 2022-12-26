package config

import (
	"reflect"
	"testing"
)

func TestRoleARNMapping(t *testing.T) {
	rm := RoleMapping{
		RoleARN:  "arn:aws:iam::012345678912:role/KubeAdmin",
		Username: "admin",
		Groups:   []string{"system:masters"},
	}

	expectedKey := "arn:aws:iam::012345678912:role/kubeadmin"
	actualKey := rm.Key()

	if !reflect.DeepEqual(actualKey, expectedKey) {
		t.Errorf("RoleMapping.Key() does not match expected value.\nActual:   %v\nExpected: %v", actualKey, expectedKey)
	}

	expectedMatch := "arn:aws:iam::012345678912:role/KubeAdmin"
	matches := rm.Matches(expectedMatch)
	if !matches {
		t.Errorf("RoleMapping %v did not match %s", rm, expectedMatch)
	}

	unexpectedMatch := "arn:aws:iam::012345678912:role/notKubeAdmin"
	matches = rm.Matches(unexpectedMatch)
	if matches {
		t.Errorf("RoleMapping %v unexpectedly matched %s", rm, unexpectedMatch)
	}

	err := rm.Validate()
	if err != nil {
		t.Errorf("Received error %v validating RoleMapping %v", err, rm)
	}

	invalidRoleMapping := RoleMapping{
		RoleARN: "",
	}
	err = invalidRoleMapping.Validate()
	if err == nil {
		t.Errorf("Invalid RoleMapping %v did not raise error when validated", invalidRoleMapping)
	}
}

func TestUserARNMapping(t *testing.T) {
	um := UserMapping{
		UserARN:  "arn:aws:iam::012345678912:user/Shanice",
		Username: "Shanice",
		Groups:   []string{"system:masters"},
	}

	expectedKey := "arn:aws:iam::012345678912:user/Shanice"
	actualKey := um.Key()

	if !reflect.DeepEqual(actualKey, expectedKey) {
		t.Errorf("UserMapping.Key() does not match expected value.\nActual:   %v\nExpected: %v", actualKey, expectedKey)
	}

	expectedMatch := "arn:aws:iam::012345678912:user/shanice"
	matches := um.Matches(expectedMatch)
	if !matches {
		t.Errorf("UserMapping %v did not match %s", um, expectedMatch)
	}

	unexpectedMatch := "arn:aws:iam::012345678912:user/notShanice"
	matches = um.Matches(unexpectedMatch)
	if matches {
		t.Errorf("UserMapping %v unexpectedly matched %s", um, unexpectedMatch)
	}

	err := um.Validate()
	if err != nil {
		t.Errorf("Received error %v validating UserMapping %v", err, um)
	}

	invalidUserMapping := UserMapping{
		UserARN: "",
	}
	err = invalidUserMapping.Validate()
	if err == nil {
		t.Errorf("Invalid UserMapping %v did not raise error when validated", invalidUserMapping)
	}
}
