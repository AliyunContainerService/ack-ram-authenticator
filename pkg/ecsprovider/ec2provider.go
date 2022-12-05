package ec2provider

import (
	"time"
)

const (
	// max limit of k8s nodes support
	maxChannelSize = 8000
	// max number of in flight non batched ec2:DescribeInstances request to flow
	maxAllowedInflightRequest = 5
	// default wait interval for the ec2 instance id request which is already in flight
	defaultWaitInterval = 50 * time.Millisecond
	// Making sure the single instance calls waits max till 5 seconds 100* (50 * time.Millisecond)
	totalIterationForWaitInterval = 100
	// Maximum number of instances with which ec2:DescribeInstances call will be made
	maxInstancesBatchSize = 100
	// Maximum time in Milliseconds to wait for a new batch call this also depends on if the instance size has
	// already become 100 then it will not respect this limit
	maxWaitIntervalForBatch = 200
)
