package arn

import (
	"fmt"
	"testing"
)

var arnTests = []struct {
	arn      string // input arn
	expected string // canonacalized arn
	err      error  // expected error value
}{
	{"NOT AN ARN", "", fmt.Errorf("Not an arn")},
	{"acs:ram::123456789012:user/Alice", "acs:ram::123456789012:user/Alice", nil},
	{"acs:ram::123456789012:role/Users", "acs:ram::123456789012:role/Users", nil},
	{"acs:ram::123456789012:assumed-role/Admin/Session", "acs:ram::123456789012:role/Admin", nil},
}

func TestUserARN(t *testing.T) {
	for _, tc := range arnTests {
		actual, err := Canonicalize(tc.arn)
		if err != nil && tc.err == nil || err == nil && tc.err != nil {
			t.Errorf("Canoncialize(%s) expected err: %v, actual err: %v", tc.arn, tc.err, err)
			continue
		}
		if actual != tc.expected {
			t.Errorf("Canonicalize(%s) expected: %s, actual: %s", tc.arn, tc.expected, actual)
		}
	}
}
