package token

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	userAgentV2 = "ack-ram-authenticator/v2"
	userAgentV1 = "ack-ram-authenticator/v1"
)

var reCredential = regexp.MustCompile(`Credential=([^,]+),`)

type V2Token struct {
	ClusterId string `json:"clusterId"`

	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   map[string]string `json:"query"`
	Headers map[string]string `json:"headers"`
}

func (v tokenVerifier) parseV2Token(rawToken string) (string, *http.Request, error) {
	var t V2Token
	rawToken = strings.TrimPrefix(rawToken, v2Prefix)

	if err := json.Unmarshal([]byte(rawToken), &t); err != nil {
		log.Warnf("parse token failed: %+v", err)
		return "", nil, err
	}
	if err := v.verifyClusterID(t.ClusterId); err != nil {
		log.Warnf("[%s] found unexpected clusterId from token: %+v", v.clusterID, t.ClusterId)
		return "", nil, err
	}

	reqURL := fmt.Sprintf("https://%s", v.stsEndpoint)
	if u, err := url.ParseRequestURI(t.Path); err == nil && u != nil {
		reqURL = reqURL + u.Path
	}
	req, err := http.NewRequest(strings.ToUpper(t.Method), reqURL, nil)
	if err != nil {
		return "", nil, err
	}

	query := req.URL.Query()
	for k, vs := range t.Query {
		if !parameterWhitelist[strings.ToLower(k)] {
			continue
		}
		if len(vs) > 0 {
			query.Set(k, vs)
		}
	}
	req.URL.RawQuery = query.Encode()

	for k, vs := range t.Headers {
		if !parameterWhitelist[strings.ToLower(k)] {
			continue
		}
		if len(vs) > 0 {
			req.Header.Set(k, vs)
		}
	}
	req.Header.Set("User-Agent", userAgentV2)

	accessKeyId := getAccessKeyIdFromV2Header(req.Header.Get("Authorization"))

	return accessKeyId, req, nil
}

func getAccessKeyIdFromV2Header(rawV string) string {
	parts := reCredential.FindAllStringSubmatch(rawV, -1)
	if len(parts) < 1 {
		return ""
	}
	if len(parts[0]) < 2 {
		return ""
	}
	return parts[0][1]
}
