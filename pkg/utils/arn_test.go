package utils

import (
	"strings"
	"testing"
)

// TestParse tests the functionality of the Parse function with different input cases:
// 1. Empty string
// 2. String without the proper prefix
// 3. String with missing sections despite having the correct prefix
// 4. Fully valid ARN string
func TestParse(t *testing.T) {
	t.Run("EmptyString", func(t *testing.T) {
		_, err := Parse("")
		if err == nil || err.Error() != invalidPrefix {
			t.Errorf("Expected error: %s, got: %v", invalidPrefix, err)
		}
	})

	t.Run("InvalidPrefix", func(t *testing.T) {
		_, err := Parse("not" + arnPrefix)
		if err == nil || err.Error() != invalidPrefix {
			t.Errorf("Expected error: %s, got: %v", invalidPrefix, err)
		}
	})

	t.Run("MissingSections", func(t *testing.T) {
		_, err := Parse(strings.Join([]string{arnPrefix, "ram"}, arnDelimiter))
		if err == nil || err.Error() != invalidSections {
			t.Errorf("Expected error: %s, got: %v", invalidSections, err)
		}
	})

	t.Run("ValidARN", func(t *testing.T) {
		arn, err := Parse("acs:ram::1234567890:user/David")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if arn.AccountID != "1234567890" || arn.Service != "ram" || arn.Region != "" || arn.Partition != "acs" || arn.Resource != "user/David" {
			t.Errorf("Expected arn: %+v, got: %+v", ARN{
				Partition: "acs",
				Service:   "ram",
				Region:    "",
				AccountID: "1234567890",
				Resource:  "user/David",
			}.String(), arn.String())
		}
	})
}

// TestARNString verifies that the String method returns the correct ARN representation:
// 1. Input with a fully populated ARN struct
func TestARNString(t *testing.T) {
	arn := ARN{
		Partition: "partition",
		Service:   "service",
		Region:    "region",
		AccountID: "accountID",
		Resource:  "resource",
	}

	expectedARNStr := arnPrefix + "service" + arnDelimiter + "region" + arnDelimiter + "accountID" + arnDelimiter + "resource"
	actualARNStr := arn.String()
	if expectedARNStr != actualARNStr {
        t.Errorf("Expected ARN string %s, got %s", expectedARNStr, actualARNStr)
    }
}
