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

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/metrics"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/token"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/prometheus/client_golang/prometheus"
)

func Test_newDenyTokenReview(t *testing.T) {
	type args struct {
		err  error
		meta metav1.TypeMeta
	}
	tests := []struct {
		name string
		args args
		want authenticationv1beta1.TokenReview
	}{
		{
			"testFormatError",
			args{
				err:  token.FormatError{},
				meta: metav1.TypeMeta{},
			},
			authenticationv1beta1.TokenReview{
				TypeMeta: metav1.TypeMeta{},
				Status: authenticationv1beta1.TokenReviewStatus{
					Authenticated: false,
					Error:         "[ack-ram-authenticator] parse token failed. input token was not properly formatted: ",
				},
			},
		},
		{
			"testSTSError",
			args{
				err:  token.STSError{},
				meta: metav1.TypeMeta{},
			},
			authenticationv1beta1.TokenReview{
				TypeMeta: metav1.TypeMeta{},
				Status: authenticationv1beta1.TokenReviewStatus{
					Authenticated: false,
					Error:         "[ack-ram-authenticator] invalid token",
				},
			},
		},
		{
			"testMappingError",
			args{
				err:  MappingError{err: errors.New("test")},
				meta: metav1.TypeMeta{},
			},
			authenticationv1beta1.TokenReview{
				TypeMeta: metav1.TypeMeta{},
				Status: authenticationv1beta1.TokenReviewStatus{
					Authenticated: false,
					Error:         "[ack-ram-authenticator] invalid token. test",
				},
			},
		},
		{
			"testOther",
			args{
				err:  errors.New(""),
				meta: metav1.TypeMeta{},
			},
			authenticationv1beta1.TokenReview{
				TypeMeta: metav1.TypeMeta{},
				Status: authenticationv1beta1.TokenReviewStatus{
					Authenticated: false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newDenyTokenReview(tt.args.err, tt.args.meta); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newDenyTokenReview() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testVerifier struct {
	identity *token.Identity
	err      error
	param    string
}

func (v *testVerifier) Verify(token string) (*token.Identity, error) {
	v.param = token
	return v.identity, v.err
}

func Test_handler_authenticateEndpoint(t *testing.T) {
	mapResp := map[string]*httptest.ResponseRecorder{
		"testPost":              httptest.NewRecorder(),
		"testEmptyBody":         httptest.NewRecorder(),
		"testInvalidBody":       httptest.NewRecorder(),
		"testVerifierError":     httptest.NewRecorder(),
		"testVerifierStsError":  httptest.NewRecorder(),
		"testVerifierNotMapped": httptest.NewRecorder(),
	}
	metrics.InitMetrics(prometheus.NewRegistry())
	data, err := json.Marshal(authenticationv1beta1.TokenReview{
		Spec: authenticationv1beta1.TokenReviewSpec{
			Token: "token",
		},
	})
	if err != nil {
		t.Fatalf("Could not marshal in put data: %v", err)
	}

	type args struct {
		w   http.ResponseWriter
		req *http.Request
	}
	tests := []struct {
		name     string
		h        *handler
		args     args
		want     int
		wantBody string
	}{
		{"testPost",
			&handler{},
			args{
				mapResp["testPost"],
				httptest.NewRequest("GET", "http://example.com", nil),
			},
			http.StatusMethodNotAllowed,
			"expected POST",
		},

		{"testEmptyBody",
			&handler{},
			args{
				mapResp["testEmptyBody"],
				httptest.NewRequest("POST", "http://example.com", nil),
			},
			http.StatusBadRequest,
			"expected a request body",
		},

		{"testInvalidBody",
			&handler{},
			args{
				mapResp["testInvalidBody"],
				httptest.NewRequest("POST", "http://example.com", strings.NewReader("not valid json")),
			},
			http.StatusBadRequest,
			"expected a request body to be a TokenReview",
		},

		{"testVerifierError",
			&handler{
				verifier: &testVerifier{
					err: errors.New("this is a error"),
				},
			},
			args{
				mapResp["testVerifierError"],
				httptest.NewRequest("POST", "http://example.com",
					bytes.NewReader(data)),
			},
			http.StatusOK,
			"{\"metadata\":{\"creationTimestamp\":null},\"spec\":{},\"status\":{\"user\":{},\"error\":\"[ack-ram-authenticator] invalid token\"}}"},

		{"testVerifierStsError",
			&handler{
				verifier: &testVerifier{
					err: token.NewSTSError("There was an error"),
				},
			},
			args{
				mapResp["testVerifierStsError"],
				httptest.NewRequest("POST", "http://example.com", bytes.NewReader(data)),
			},
			http.StatusOK,
			"{\"metadata\":{\"creationTimestamp\":null},\"spec\":{},\"status\":{\"user\":{},\"error\":\"[ack-ram-authenticator] invalid token\"}}",
		},

		{"testVerifierNotMapped",
			&handler{
				verifier: &testVerifier{
					err: nil,
					identity: &token.Identity{
						ARN:          "",
						CanonicalARN: "",
						AccountID:    "",
						UserID:       "",
						SessionName:  "",
					},
				},
			},
			args{
				mapResp["testVerifierNotMapped"],
				httptest.NewRequest("POST", "http://example.com",
					bytes.NewReader(data)),
			},
			http.StatusOK,
			"{\"metadata\":{\"creationTimestamp\":null},\"spec\":{},\"status\":{\"user\":{},\"error\":\"[ack-ram-authenticator] invalid token. ARN is not mapped\"}}",
		},
	}
	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			tt.h.authenticateEndpoint(tt.args.w, tt.args.req)
			if mapResp[tt.name].Code != tt.want {
				t.Errorf("Expected status code %d, was %d", tt.want, mapResp[tt.name].Code)
			}

			b, err := ioutil.ReadAll(mapResp[tt.name].Body)
			if err != nil {
				t.Fatalf("Failed to read body from ResponseRecorder, this should not happen")
			}
			if !strings.Contains(string(b), tt.wantBody) {
				t.Errorf("Expected body %s, was %s", tt.wantBody, string(b))
			}
		})
	}
}
