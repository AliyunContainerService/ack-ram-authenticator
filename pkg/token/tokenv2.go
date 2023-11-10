package token

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

const userAgent = "ack-ram-authenticator/v2"

type V2Token struct {
	ClusterId string `json:"clusterId"`

	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   map[string]string `json:"query"`
	Headers map[string]string `json:"headers"`
}

func (v tokenVerifier) parseV2Token(rawToken string) (*http.Request, error) {
	var t V2Token
	rawToken = strings.TrimPrefix(rawToken, v2Prefix)

	if err := json.Unmarshal([]byte(rawToken), &t); err != nil {
		log.Warnf("parse token failed: %+v", err)
		return nil, err
	}
	if err := v.verifyClusterID(t.ClusterId); err != nil {
		log.Warnf("[%s] found unexpected clusterId from token: %+v", v.clusterID, t.ClusterId)
		return nil, err
	}

	reqURL := fmt.Sprintf("https://%s", v.stsEndpoint)
	if u, err := url.ParseRequestURI(t.Path); err == nil && u != nil {
		reqURL = reqURL + u.Path
	}
	req, err := http.NewRequest(strings.ToUpper(t.Method), reqURL, nil)
	if err != nil {
		return nil, err
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
	req.Header.Set("User-Agent", userAgent)

	return req, nil
}
