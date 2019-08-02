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
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha1"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/arn"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
	acsSts "github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/satori/go.uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1alpha1 "k8s.io/client-go/pkg/apis/clientauthentication/v1alpha1"
	"os/user"
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
}

const (
	// The actual token expiration (presigned STS urls are valid for 15 minutes after timestamp in query param Timestamp).
	presignedURLExpiration = 15 * time.Minute
	v1Prefix               = "k8s-ack-v1."
	maxTokenLenBytes       = 1024 * 4
	hostRegexp             = `^sts(\.[a-z1-9\-]+)?\.aliyuncs\.com(\.cn)?$`
	stsSignVersion         = "1.0"
	stsAPIVersion          = "2015-04-01"
	stsHost                = "https://sts.aliyuncs.com/"
	timeFormat             = "2006-01-02T15:04:05Z"
	respBodyFormat         = "JSON"
	percentEncode          = "%2F"
	httpGet                = "GET"
)

// Token is generated and used by Kubernetes client-go to authenticate with a Kubernetes cluster.
type Token struct {
	Token      string
	Expiration time.Time
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
	message string
}

func (e STSError) Error() string {
	return "sts getCallerIdentity failed: " + e.message
}

// NewSTSError creates a error of type STS.
func NewSTSError(m string) STSError {
	return STSError{message: m}
}

var parameterWhitelist = map[string]bool{
	"action":           true,
	"durationseconds":  true,
	"signatureversion": true,
	"signaturenonce":   true,
	"signaturemethod":  true,
	"accesskeyid":      true,
	"timestamp":        true,
	"signature":        true,
	"format":           true,
	"version":          true,
	"rolesessionname":  true,
	"rolearn":          true,
	"securitytoken":    true,
	"clusterid":        true,
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

type acsCredentials struct {
	AccessKeyID         string `json:"AcsAccessKeyId"`
	AccessKeySecret     string `json:"AcsAccessKeySecret"`
	AccessSecurityToken string `json:"AcsAccessSecurityToken"`
}

// JSONStruct struct
type JSONStruct struct {
}

// Generator provides new tokens for the authenticator.
type Generator interface {
	// Get a token using credentials in the default credentials chain.
	Get(string) (Token, error)
	// GetWithRole creates a token by assuming the provided role, using the credentials in the default chain.
	GetWithRole(clusterID, roleARN string) (Token, error)
	// FormatJSON returns the client auth formatted json for the ExecCredential auth
	FormatJSON(Token) string
}

type generator struct {
}

// NewGenerator creates a Generator and returns it.
func NewGenerator() (Generator, error) {
	return generator{}, nil
}

// Get uses the directly available RAM credentials to return a token valid for
// clusterID. It follows the default RAM credential handling behavior.
func (g generator) Get(clusterID string) (Token, error) {
	return g.GetWithRole(clusterID, "")
}

// StdinStderrTokenProvider func
func StdinStderrTokenProvider() (string, error) {
	var v string
	fmt.Fprint(os.Stderr, "Assume Role MFA token code: ")
	_, err := fmt.Scanln(&v)
	return v, err
}

func (g generator) GetWithRole(clusterID string, roleARN string) (Token, error) {
	var getCallerIdentityURL string
	var err error
	JSONParse := NewJSONStruct()
	v := acsCredentials{}
	credentialsFile := getCredentialsFile()
	JSONParse.Load(credentialsFile, &v)
	tokenExpiration := time.Now().Local().Add(presignedURLExpiration - 1*time.Minute)
	if v.AccessSecurityToken != "" {
		getCallerIdentityURL, err = apiCaller(v.AccessKeyID, v.AccessKeySecret, v.AccessSecurityToken, clusterID)
		if err != nil {
			return Token{}, err
		}
	} else if roleARN != "" {
		assumeClient, err := acsSts.NewClientWithAccessKey("", v.AccessKeyID, v.AccessKeySecret)
		if err != nil {
			return Token{}, fmt.Errorf("could not assume role with provided AK: %v", err)
		}
		request := acsSts.CreateAssumeRoleRequest()
		request.Scheme = "https"
		request.RoleArn = roleARN
		request.RoleSessionName = "ack-ram-session"
		resp, err := assumeClient.AssumeRole(request)

		if err != nil {
			return Token{}, err
		}
		getCallerIdentityURL, err = apiCaller(resp.Credentials.AccessKeyId, resp.Credentials.AccessKeySecret, resp.Credentials.SecurityToken, clusterID)
		if err != nil {
			return Token{}, err
		}
		//return Token{v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(getCallerIdentityURL)), tokenExpiration}, nil
	} else {
		getCallerIdentityURL, err = apiCaller(v.AccessKeyID, v.AccessKeySecret, "", clusterID)
		if err != nil {
			return Token{}, err
		}
	}
	return Token{v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(getCallerIdentityURL)), tokenExpiration}, nil
}

// FormatJSON formats the json to support ExecCredential authentication
func (g generator) FormatJSON(token Token) string {
	expirationTimestamp := metav1.NewTime(token.Expiration)
	execInput := &clientauthv1alpha1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1alpha1",
			Kind:       "ExecCredential",
		},
		Status: &clientauthv1alpha1.ExecCredentialStatus{
			ExpirationTimestamp: &expirationTimestamp,
			Token:               token.Token,
		},
	}
	enc, _ := json.Marshal(execInput)
	return string(enc)
}

// Verifier validates tokens by calling STS and returning the associated identity.
type Verifier interface {
	Verify(token string) (*Identity, error)
}

type tokenVerifier struct {
	client    *http.Client
	clusterID string
}

func (v tokenVerifier) getClusterID() string {
	return v.clusterID
}

// NewVerifier creates a Verifier that is bound to the clusterID and uses the default http client.
func NewVerifier(clusterID string) Verifier {
	return tokenVerifier{
		client:    http.DefaultClient,
		clusterID: clusterID,
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
		return FormatError{fmt.Sprintf("unexpected clusterid %s in pre-signed URL", clusterID)}
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

	if !strings.HasPrefix(token, v1Prefix) {
		return nil, FormatError{fmt.Sprintf("token is missing expected %q prefix", v1Prefix)}
	}

	// TODO: this may need to be a constant-time base64 decoding
	tokenBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, v1Prefix))
	if err != nil {
		return nil, FormatError{err.Error()}
	}

	parsedURL, err := url.Parse(string(tokenBytes))
	if err != nil {
		return nil, FormatError{err.Error()}
	}

	if parsedURL.Scheme != "https" {
		return nil, FormatError{fmt.Sprintf("unexpected scheme %q in pre-signed URL", parsedURL.Scheme)}
	}

	if err = v.verifyHost(parsedURL.Host); err != nil {
		return nil, err
	}

	if parsedURL.Path != "/" {
		return nil, FormatError{"unexpected path in pre-signed URL"}
	}

	queryParamsLower := make(url.Values)
	queryParams := parsedURL.Query()
	for key, values := range queryParams {
		if !parameterWhitelist[strings.ToLower(key)] {
			return nil, FormatError{fmt.Sprintf("non-whitelisted query parameter %q", key)}
		}
		if len(values) != 1 {
			return nil, FormatError{"query parameter with multiple values not supported"}
		}
		queryParamsLower.Set(strings.ToLower(key), values[0])
	}

	if queryParamsLower.Get("action") != "GetCallerIdentity" {
		return nil, FormatError{"unexpected action parameter in pre-signed URL"}
	}

	if err = v.verifyClusterID(queryParamsLower.Get("clusterid")); err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	req.Header.Set("accept", "application/json")

	response, err := v.client.Do(req)
	if err != nil {
		// special case to avoid printing the full URL if possible
		if urlErr, ok := err.(*url.Error); ok {
			return nil, NewSTSError(fmt.Sprintf("error during GET: %v", urlErr.Err))
		}
		return nil, NewSTSError(fmt.Sprintf("error during GET: %v", err))
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, NewSTSError(fmt.Sprintf("error from RAM (expected 200, got %d)", response.StatusCode))
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, NewSTSError(fmt.Sprintf("error reading HTTP result: %v", err))
	}

	var callerIdentity getCallerIdentityWrapper
	err = json.Unmarshal(responseBody, &callerIdentity)
	if err != nil {
		return nil, NewSTSError(err.Error())
	}

	// parse the response into an Identity
	id := &Identity{
		ARN:       callerIdentity.Arn,
		AccountID: callerIdentity.AccountID,
	}
	id.CanonicalARN, err = arn.Canonicalize(id.ARN)
	if err != nil {
		return nil, NewSTSError(err.Error())
	}

	// The user ID is either UserID:SessionName (for assumed roles) or just
	// UserID (for RAM User principals).
	userIDParts := strings.Split(callerIdentity.PrincipalID, ":")
	if len(userIDParts) == 2 {
		id.UserID = userIDParts[0]
		id.SessionName = userIDParts[1]
	} else if len(userIDParts) == 1 {
		id.UserID = userIDParts[0]
	} else {
		return nil, STSError{fmt.Sprintf(
			"malformed UserID %q",
			callerIdentity.PrincipalID)}
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

// Get credentials from HomeDir
func getCredentialsFile() string {
	usr, err := user.Current()
	if err != nil {
		fmt.Println("Error:", err)
	}
	return usr.HomeDir + "/.acs/credentials"
}

// Generate api call url
func apiCaller(AccessKeyID, AccessKeySecret, SecurityToken, clusterID string) (string, error) {
	queryStr := "SignatureVersion=" + stsSignVersion
	queryStr += "&Format=" + respBodyFormat
	queryStr += "&Timestamp=" + url.QueryEscape(time.Now().UTC().Format(timeFormat))
	queryStr += "&AccessKeyId=" + AccessKeyID
	queryStr += "&SignatureMethod=HMAC-SHA1"
	queryStr += "&Version=" + stsAPIVersion
	queryStr += "&SignatureNonce=" + uuid.NewV4().String()
	queryStr += "&Action=GetCallerIdentity"
	queryStr += "&ClusterId=" + clusterID
	if SecurityToken != "" {
		queryStr += "&SecurityToken=" + url.QueryEscape(SecurityToken)
	}

	queryParams, err := url.ParseQuery(queryStr)

	if err != nil {
		return "", err
	}
	result := queryParams.Encode()

	strToSign := httpGet + "&" + percentEncode + "&" + url.QueryEscape(result)
	hashSign := hmac.New(sha1.New, []byte(AccessKeySecret+"&"))
	hashSign.Write([]byte(strToSign))
	signature := base64.StdEncoding.EncodeToString(hashSign.Sum(nil))

	// Build url
	getCallerIdentityURL := stsHost + "?" + queryStr + "&Signature=" + url.QueryEscape(signature)
	return getCallerIdentityURL, nil
}
