package utils

import (
	"errors"
	"strings"
)

const (
	arnDelimiter = ":"
	arnSections  = 5
	arnPrefix    = "acs:"

	// zero-indexed
	sectionPartition = 0
	sectionService   = 1
	sectionRegion    = 2
	sectionAccountID = 3
	sectionResource  = 4

	// errors
	invalidPrefix   = "acs: invalid prefix"
	invalidSections = "acs: not enough sections"
)

// ARN captures the individual fields of an RAM Resource Name.
type ARN struct {
	// The partition that the resource is in.
	Partition string

	// The service namespace that identifies the product (for example, RAM).
	Service string

	// The region the resource resides in. Note that the ARNs for some resources do not require a region, so this
	// component might be omitted.
	Region string

	// The ID of the RAM account that owns the resource, without the hyphens. For example, 123456789012. Note that the
	// ARNs for some resources don't require an account number, so this component might be omitted.
	AccountID string

	// The content of this part of the ARN varies by service.
	Resource string
}

// Parse parses an ARN into its constituent parts.
//
// Some example ARNs:
// acs:ram::123456789012:user/David
// acs:ram::123456789012:role/Defaultrole
func Parse(arn string) (ARN, error) {
	if !strings.HasPrefix(arn, arnPrefix) {
		return ARN{}, errors.New(invalidPrefix)
	}
	sections := strings.SplitN(arn, arnDelimiter, arnSections)
	if len(sections) != arnSections {
		return ARN{}, errors.New(invalidSections)
	}
	return ARN{
		Partition: sections[sectionPartition],
		Service:   sections[sectionService],
		Region:    sections[sectionRegion],
		AccountID: sections[sectionAccountID],
		Resource:  sections[sectionResource],
	}, nil
}

// String returns the canonical representation of the ARN
func (arn ARN) String() string {
	return arnPrefix +
		//arn.Partition + arnDelimiter +
		arn.Service + arnDelimiter +
		arn.Region + arnDelimiter +
		arn.AccountID + arnDelimiter +
		arn.Resource
}
