package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

func validationErrorTest(t *testing.T, token string, expectedErr string) {
	t.Helper()
	_, err := tokenVerifier{}.Verify(token)
	errorContains(t, err, expectedErr)
}

func errorContains(t *testing.T, err error, expectedErr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("err should have contained '%s' was '%s'", expectedErr, err)
	}
}

func assertSTSError(t *testing.T, err error) {
	t.Helper()
	if _, ok := err.(STSError); !ok {
		t.Errorf("Expected err %v to be an STSError but was not", err)
	}
}

var (
	now        = time.Now()
	timeStr    = now.UTC().Format("2006-01-02T15:04:05Z")
	validToken = v2Prefix + "eyJjbHVzdGVySWQiOiJjMmZhZjRmNzU4NGUzNDljZGE2ZGRhMmEqKioqKioqKioiLCJtZXRob2QiOiJQT1NUIiwicGF0aCI6Ii8iLCJxdWVyeSI6eyJBQ0tDbHVzdGVySWQiOiJjMmZhZjRmNzU4NGUzNDljZGE2ZGRhMmEqKioqKioqKioifSwiaGVhZGVycyI6eyJBdXRob3JpemF0aW9uIjoiQUNTMy1ITUFDLVNIQTI1NiBDcmVkZW50aWFsPSoqKioqKioqKioqKlNKR1cyQioqKioqKixTaWduZWRIZWFkZXJzPXgtYWNzLWFjdGlvbjt4LWFjcy1jb250ZW50LXNoYTI1Njt4LWFjcy1kYXRlO3gtYWNzLXZlcnNpb24sU2lnbmF0dXJlPTgwMzg1NDgzMDk5Mjc0ZWVmMDA0OGE0OTFiYzIyMDkyMWM1ZTE5NWE4M2I3ZmRkZTNmNzBjOTBjMjk2NjVmMGYiLCJ1c2VyLWFnZW50IjoiYWNrLXJhbS10b29sL3YwLjAuMCAoZGFyd2luL2FybTY0KSIsIngtYWNzLWFjdGlvbiI6IkdldENhbGxlcklkZW50aXR5IiwieC1hY3MtY29udGVudC1zaGEyNTYiOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwieC1hY3MtZGF0ZSI6IjIwMjQtMDctMzFUMTE6MzU6MjRaIiwieC1hY3MtdmVyc2lvbiI6IjIwMTUtMDQtMDEifX0="
)

func newVerifier(statusCode int, body string, err error) Verifier {
	var rc io.ReadCloser
	if body != "" {
		rc = ioutil.NopCloser(bytes.NewReader([]byte(body)))
	}
	return tokenVerifier{
		clusterID: "c2faf4f7584e349cda6dda2a*********",
		client: &http.Client{
			Transport: &roundTripper{
				err: err,
				resp: &http.Response{
					StatusCode: statusCode,
					Body:       rc,
				},
			},
		},
	}
}

type roundTripper struct {
	err  error
	resp *http.Response
}

type errorReadCloser struct {
}

func (r errorReadCloser) Read(b []byte) (int, error) {
	return 0, errors.New("An Error")
}

func (r errorReadCloser) Close() error {
	return nil
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.resp, rt.err
}

func jsonResponse(arn, account, userid string) string {
	response := getCallerIdentityWrapper{}
	response.AccountID = account
	response.Arn = arn
	response.UserID = userid
	response.PrincipalID = userid
	data, _ := json.Marshal(response)
	return string(data)
}

func TestVerifyHTTPError(t *testing.T) {
	_, err := newVerifier(0, "", errors.New("an error")).Verify(validToken)
	errorContains(t, err, "call sts.GetCallerIdentity failed: Bad Request, an error")
	assertSTSError(t, err)
}

func TestVerifyHTTP403(t *testing.T) {
	_, err := newVerifier(403, " ", nil).Verify(validToken)
	errorContains(t, err, "call sts.GetCallerIdentity failed: Forbidden")
	assertSTSError(t, err)
}

func TestVerifyBodyReadError(t *testing.T) {
	verifier := tokenVerifier{
		clusterID: "c2faf4f7584e349cda6dda2a*********",
		client: &http.Client{
			Transport: &roundTripper{
				err: nil,
				resp: &http.Response{
					StatusCode: 200,
					Body:       errorReadCloser{},
				},
			},
		},
	}
	_, err := verifier.Verify(validToken)
	errorContains(t, err, "error reading HTTP result")
	assertSTSError(t, err)
}

func TestVerifyUnmarshalJSONError(t *testing.T) {
	_, err := newVerifier(200, "xxxx", nil).Verify(validToken)
	errorContains(t, err, "invalid character")
	assertSTSError(t, err)
}

func TestVerifyInvalidCanonicalARNError(t *testing.T) {
	_, err := newVerifier(200, jsonResponse("arn", "1000", "userid"), nil).Verify(validToken)
	errorContains(t, err, "arn 'arn' is invalid:")
	assertSTSError(t, err)
}

func TestVerifyInvalidUserIDError(t *testing.T) {
	_, err := newVerifier(200, jsonResponse("acs:ram::123456789012:user/Alice", "123456789012", "not:vailid:userid"), nil).Verify(validToken)
	errorContains(t, err, "malformed UserID")
	assertSTSError(t, err)
}

func TestVerifyNoSession(t *testing.T) {
	arn := "acs:ram::123456789012:user/Alice"
	account := "123456789012"
	userID := "Alice"
	identity, err := newVerifier(200, jsonResponse(arn, account, userID), nil).Verify(validToken)
	if err != nil {
		t.Errorf("expected error to be nil was %q", err)
	}
	if identity.ARN != arn {
		t.Errorf("expected ARN to be %q but was %q", arn, identity.ARN)
	}
	if identity.CanonicalARN != arn {
		t.Errorf("expected CannonicalARN to be %q but was %q", arn, identity.CanonicalARN)
	}
	if identity.UserID != userID {
		t.Errorf("expected Username to be %q but was %q", userID, identity.UserID)
	}
}

func TestVerifySessionName(t *testing.T) {
	arn := "acs:ram::123456789012:user/Alice"
	account := "123456789012"
	userID := "Alice"
	session := "session-name"
	identity, err := newVerifier(200, jsonResponse(arn, account, userID+":"+session), nil).Verify(validToken)
	if err != nil {
		t.Errorf("expected error to be nil was %q", err)
	}
	if identity.UserID != userID {
		t.Errorf("expected Username to be %q but was %q", userID, identity.UserID)
	}
	if identity.SessionName != session {
		t.Errorf("expected Session to be %q but was %q", session, identity.SessionName)
	}
}

func TestVerifyCanonicalARN(t *testing.T) {
	arn := "acs:ram::123456789012:assumed-role/Alice/extra"
	canonicalARN := "acs:ram::123456789012:role/Alice"
	account := "123456789012"
	userID := "Alice"
	session := "session-name"
	identity, err := newVerifier(200, jsonResponse(arn, account, userID+":"+session), nil).Verify(validToken)
	if err != nil {
		t.Errorf("expected error to be nil was %q", err)
	}
	if identity.ARN != arn {
		t.Errorf("expected ARN to be %q but was %q", arn, identity.ARN)
	}
	if identity.CanonicalARN != canonicalARN {
		t.Errorf("expected CannonicalARN to be %q but was %q", canonicalARN, identity.CanonicalARN)
	}
}
