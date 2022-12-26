package config

import (
	"fmt"
	"strings"
)

// Validate returns an error if the RoleMapping is not valid after being unmarshaled
func (m *RoleMapping) Validate() error {
	if m == nil {
		return fmt.Errorf("RoleMapping is nil")
	}

	if m.RoleARN == "" {
		return fmt.Errorf("One of rolearn must be supplied")
	} else if m.RoleARN != "" {
		return fmt.Errorf("Only one of rolearn can be supplied")
	}

	return nil
}

// Matches returns true if the supplied ARN or SSO settings matches
// this RoleMapping
func (m *RoleMapping) Matches(subject string) bool {
	return strings.ToLower(m.RoleARN) == strings.ToLower(subject)
}

// Key returns RoleARN, whichever is not empty.
// Used to get a Key name for map[string]RoleMapping
func (m *RoleMapping) Key() string {
	return strings.ToLower(m.RoleARN)
}

// Validate returns an error if the UserMapping is not valid after being unmarshaled
func (m *UserMapping) Validate() error {
	if m == nil {
		return fmt.Errorf("UserMapping is nil")
	}

	if m.UserARN == "" {
		return fmt.Errorf("Value for userarn must be supplied")
	}

	return nil
}

// Matches returns true if the supplied ARN string matche this UserMapping
func (m *UserMapping) Matches(subject string) bool {
	return strings.ToLower(m.UserARN) == strings.ToLower(subject)
}

// Key returns UserARN.
// Used to get a Key name for map[string]UserMapping
func (m *UserMapping) Key() string {
	return m.UserARN
}
