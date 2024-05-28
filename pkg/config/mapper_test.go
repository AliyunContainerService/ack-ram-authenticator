package config

import (
	"reflect"
	"testing"
)

func TestRoleARNMapping(t *testing.T) {
	rm := RoleMapping{
		RoleARN:  "acs:ram::1234567890:role/AA",
		Username: "bb",
		Groups:   []string{"system:masters"},
	}

	expectedKey := "acs:ram::1234567890:role/aa"
	actualKey := rm.Key()

	if actualKey != expectedKey {
		t.Errorf("RoleMapping.Key() does not match expected value.\nActual:   %v\nExpected: %v", actualKey, expectedKey)
	}

	expectedMatch := "acs:ram::1234567890:role/Aa"
	matches := rm.Matches(expectedMatch)
	if !matches {
		t.Errorf("RoleMapping %v did not match %s", rm, expectedMatch)
	}

	unexpectedMatch := "acs:ram::1234567890:role/bb"
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
		UserARN:  "acs:ram::1234567890:user/BB",
		Username: "Shanice",
		Groups:   []string{"system:masters"},
	}

	expectedKey := "acs:ram::1234567890:user/BB"
	actualKey := um.Key()

	if !reflect.DeepEqual(actualKey, expectedKey) {
		t.Errorf("UserMapping.Key() does not match expected value.\nActual:   %v\nExpected: %v", actualKey, expectedKey)
	}

	expectedMatch := "acs:ram::1234567890:user/bB"
	matches := um.Matches(expectedMatch)
	if !matches {
		t.Errorf("UserMapping %v did not match %s", um, expectedMatch)
	}

	unexpectedMatch := "acs:ram::1234567890:user/aa"
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
