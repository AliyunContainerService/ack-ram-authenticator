/*
Copyright 2017 by the contributors.

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

package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/arn"
	"github.com/AliyunContainerService/ack-ram-tool/pkg/credentials/provider"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Identity is returned on successful Verify() results. It contains a parsed
// version of the ACK identity used to create the token.
type Identity struct {
	// ARN is the raw RAM Resource Name returned by sts:GetCallerIdentity
	ARN string

	// CanonicalARN is the RAM Resource Name converted to a more canonical
	// representation. In particular, STS assumed role ARNs like
	// "acs:ram::ACCOUNTID:assumed-role/ROLENAME/SESSIONNAME" are converted
	// to their RAM ARN equivalent "acs:ram::ACCOUNTID:role/NAME"
	CanonicalARN string

	// AccountID is the 16 digit RAM account number.
	AccountID string

	// UserID is the unique user/role ID (e.g., "AROAAAAAAAAAAAAAAAAAA").
	UserID string

	// SessionName is the STS session name (or "" if this is not a
	// session-based identity). For ECS instance roles, this will be the ECS
	// instance ID (e.g., "iZj6c792gcdoonnp1rd5y8Z"). You should only rely on it
	// if you trust that _only_ ECS is allowed to assume the RAM Role. If RAM
	// users or other roles are allowed to assume the role, they can provide
	// (nearly) arbitrary strings here.
	SessionName string

	// The Alibaba Cloud Access Key ID used to authenticate the request.  This can be used
	// in conjunction with CloudTrail to determine the identity of the individual
	// if the individual assumed an RAM role before making the request.
	AccessKeyID string
}

const (
	v2Prefix               = "k8s-ack-v2."
	maxTokenLenBytes       = 1024 * 4
	hostRegexp             = `^sts(\.[a-z1-9\-]+)?\.aliyuncs\.com(\.cn)?$`
	defaultSTSProtocol     = "https"
	defaultRoleSessionName = "ack-ram-authenticator"
)

// Token is generated and used by Kubernetes client-go to authenticate with a Kubernetes cluster.
type Token struct {
	Token      string
	Expiration time.Time
}

// GetTokenOptions is passed to GetWithOptions to provide an extensible get token interface
type GetTokenOptions struct {
	Region        string
	ClusterID     string
	AssumeRoleARN string
}

// FormatError is returned when there is a problem with token that is
// an encoded sts request.  This can include the url, data, action or anything
// else that prevents the sts call from being made.
type FormatError struct {
	message string
}

func (e FormatError) Error() string {
	return "input token was not properly formatted: " + e.message
}

// STSError is returned when there was either an error calling STS or a problem
// processing the data returned from STS.
type STSError struct {
	message     string
	raiseToUser bool
}

func (e STSError) RaiseToUser() bool {
	return e.raiseToUser
}

func (e STSError) RawMessage() string {
	return e.message
}

func (e STSError) Error() string {
	return "sts getCallerIdentity failed: " + e.message
}

// NewSTSError creates a error of type STS.
func NewSTSError(m string) STSError {
	return STSError{message: m}
}

var parameterWhitelistV2 = map[string]bool{
	// v2
	"x-acs-action":          true,
	"x-acs-version":         true,
	"authorization":         true,
	"x-acs-signature-nonce": true,
	"x-acs-date":            true,
	"x-acs-content-sha256":  true,
	"x-acs-content-sm3":     true,
	"x-acs-security-token":  true,
	"ackclusterid":          true,
}

type getCallerIdentityWrapper struct {
	*responses.BaseResponse
	AccountID    string `json:"AccountId" xml:"AccountId"`
	UserID       string `json:"UserId" xml:"UserId"`
	RoleID       string `json:"RoleId" xml:"RoleId"`
	Arn          string `json:"Arn" xml:"Arn"`
	IdentityType string `json:"IdentityType" xml:"IdentityType"`
	PrincipalID  string `json:"PrincipalId" xml:"PrincipalId"`
	RequestID    string `json:"RequestId" xml:"RequestId"`
}

// JSONStruct struct
type JSONStruct struct {
}

// Verifier validates tokens by calling STS and returning the associated identity.
type Verifier interface {
	Verify(token string) (*Identity, error)
}

type tokenVerifier struct {
	client      *http.Client
	clusterID   string
	stsEndpoint string
}

func (v tokenVerifier) getClusterID() string {
	return v.clusterID
}

// NewVerifier creates a Verifier that is bound to the clusterID and uses the default http client.
func NewVerifier(region, clusterID string) Verifier {
	endpoint := provider.GetSTSEndpoint(region, true)
	if region == "" {
		endpoint = provider.GetSTSEndpoint(region, false)
	}
	log.Warnf("will use %s as sts endpoint", endpoint)

	rt := http.DefaultTransport.(*http.Transport).Clone()
	if v, err := strconv.Atoi(os.Getenv("STS_MAX_IDLE_CONNS_PER_HOST")); err == nil && v > 1 {
		rt.MaxIdleConnsPerHost = v
	} else {
		rt.MaxIdleConnsPerHost = 5
	}
	log.Warnf("will use %d as value of MaxIdleConnsPerHost", rt.MaxIdleConnsPerHost)

	client := &http.Client{
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return tokenVerifier{
		client:      client,
		clusterID:   clusterID,
		stsEndpoint: endpoint,
	}
}

// verify a sts host
func (v tokenVerifier) verifyHost(host string) error {
	if match, _ := regexp.MatchString(hostRegexp, host); !match {
		return FormatError{fmt.Sprintf("unexpected hostname %q in pre-signed URL", host)}
	}

	return nil
}

// verify a sts host
func (v tokenVerifier) verifyClusterID(clusterID string) error {
	if v.clusterID != clusterID {
		return FormatError{fmt.Sprintf("unexpected clusterid %s in token", clusterID)}
	}

	return nil
}

// Verify a token is valid for the specified clusterID. On success, returns an
// Identity that contains information about the RAM principal that created the
// token. On failure, returns nil and a non-nil error.
func (v tokenVerifier) Verify(token string) (*Identity, error) {
	if len(token) > maxTokenLenBytes {
		return nil, FormatError{"token is too large"}
	}

	if !strings.HasPrefix(token, v2Prefix) {
		return nil, FormatError{"token is missing expected prefix"}
	}

	// TODO: this may need to be a constant-time base64 decoding
	tokenBytes, err := base64.StdEncoding.DecodeString(
		strings.TrimPrefix(token, v2Prefix),
	)
	if err != nil {
		return nil, FormatError{err.Error()}
	}

	var req *http.Request
	var accessKeyId string
	switch {
	case strings.HasPrefix(token, v2Prefix):
		log.Infof("start to parse token with prefix %s", v2Prefix)
		accessKeyId, req, err = v.parseV2Token(string(tokenBytes))
		if err != nil {
			return nil, FormatError{err.Error()}
		}
	}

	req.Header.Set("accept", "application/json")
	response, err := v.client.Do(req)
	if err != nil {
		// special case to avoid printing the full URL if possible
		if urlErr, ok := err.(*url.Error); ok {
			log.WithError(urlErr.Err).Errorf("error during GET")
			return nil, newOpenAPIErr(http.StatusBadRequest, nil, urlErr.Err)
		}
		log.WithError(err).Errorf("error during GET")
		return nil, newOpenAPIErr(http.StatusBadRequest, nil, err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		responseBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Errorf("error from RAM (expected 200, got %d, err %v)", response.StatusCode, err)
			return nil, newOpenAPIErr(response.StatusCode, nil, nil)
		}
		log.Errorf("error from RAM (expected 200, got %d, body %s, err %v)", response.StatusCode, string(responseBytes), err)
		return nil, newOpenAPIErr(response.StatusCode, responseBytes, nil)
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf(fmt.Sprintf("error reading HTTP result: %v", err))
		return nil, newOpenAPIErr(http.StatusBadRequest, nil, fmt.Errorf("error reading HTTP result: %s", err.Error()))
	}

	var callerIdentity getCallerIdentityWrapper
	err = json.Unmarshal(responseBody, &callerIdentity)
	if err != nil {
		log.Errorf(err.Error())
		return nil, newOpenAPIErr(http.StatusBadRequest, nil, err)
	}

	// parse the response into an Identity
	id := &Identity{
		ARN:       callerIdentity.Arn,
		AccountID: callerIdentity.AccountID,
	}
	id.CanonicalARN, err = arn.Canonicalize(id.ARN)
	if err != nil {
		log.Errorf(err.Error())
		return nil, newOpenAPIErr(http.StatusBadRequest, nil, err)
	}
	id.AccessKeyID = accessKeyId

	// The user ID is either UserID:SessionName (for assumed roles) or just
	// UserID (for RAM User principals).
	userIDParts := strings.Split(callerIdentity.PrincipalID, ":")
	if len(userIDParts) == 2 {
		id.UserID = userIDParts[0]
		id.SessionName = userIDParts[1]
	} else if len(userIDParts) == 1 {
		id.UserID = userIDParts[0]
	} else {
		return nil, newOpenAPIErr(http.StatusBadRequest, nil, fmt.Errorf(
			"malformed UserID %q",
			callerIdentity.PrincipalID))
	}

	return id, nil
}

// NewJSONStruct new a json struct
func NewJSONStruct() *JSONStruct {
	return &JSONStruct{}
}

// Load file
func (jst *JSONStruct) Load(filename string, v interface{}) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &v)
	if err != nil {
		return
	}
}
