package arn

import (
	"fmt"
	"strings"

	ackArn "github.com/AliyunContainerService/ack-ram-authenticator/pkg/utils"
)

// Canonicalize validates RAM resources are appropriate for the authenticator
// and converts STS assumed roles into the RAM role resource.
//
// Supported RAM resources are:
//   * RAM user: acs:ram::123456789012:user/Bob
//   * RAM role: acs:ram::123456789012:role/Default
//   * RAM Assumed role: acs:ram::123456789012:assumed-role/Default

// Canonicalize canonicalize a string
func Canonicalize(arn string) (string, error) {
	parsed, err := ackArn.Parse(arn)
	if err != nil {
		return "", fmt.Errorf("arn '%s' is invalid: '%v'", arn, err)
	}

	if err := checkPartition(parsed.Partition); err != nil {
		return "", fmt.Errorf("arn '%s' does not have a recognized partition", arn)
	}

	parts := strings.Split(parsed.Resource, "/")
	resource := parts[0]

	switch parsed.Service {
	case "ram":
		switch resource {
		case "role", "user", "root":
			return arn, nil
		case "assumed-role":
			if len(parts) < 3 {
				return "", fmt.Errorf("assumed-role arn '%s' does not have a role", arn)
			}
			role := strings.Join(parts[1:len(parts)-1], "/")
			return fmt.Sprintf("acs:ram::%s:role/%s", parsed.AccountID, role), nil
		default:
			return "", fmt.Errorf("unrecognized resource %s for service ram", parsed.Resource)
		}
	}

	return "", fmt.Errorf("service %s in arn %s is not a valid service for identities", parsed.Service, arn)
}

func checkPartition(partition string) error {
	switch partition {
	case "acs":
	default:
		return fmt.Errorf("partion %s is not recognized", partition)
	}
	return nil
}
