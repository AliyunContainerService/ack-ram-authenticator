package utils

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRequestWithHeader_1 tests a successful request with valid data, no timeout, expecting status code 200
func TestRequestWithHeader_1(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	data := struct {
		Field string `json:"field"`
	}{Field: "value"}
	header := make(http.Header)
	header.Add("X-Custom-Header", "custom-value")
	urlStr := mockServer.URL

	statusCode, err := requestWithHeader(http.MethodPost, urlStr, data, header, []byte{}, 0)
	if statusCode != http.StatusOK || err != nil {
		t.Errorf("requestWithHeader failed, statusCode: %d, err: %v", statusCode, err)
	}
}

// TestRequestWithHeader_2 tests JSON marshaling failure scenario
func TestRequestWithHeader_2(t *testing.T) {
	data := map[string]interface{}{
		"key1": "value1",
		"key2": make(chan int),
	}
	header := make(http.Header)
	urlStr := "http://example.com"

	_, err := requestWithHeader(http.MethodPost, urlStr, data, header, []byte{}, 0)
	execptedErrStr := "json: unsupported type: chan int"

	if err == nil || err.Error() != execptedErrStr {
		t.Errorf("Expected error: %s, got: %v", execptedErrStr, err)
  }
}

// TestRequestWithHeader_3 tests failure when creating a new request
func TestRequestWithHeader_3(t *testing.T) {
	bodyData := []byte(`{"key": "value"}`)
	header := make(http.Header)
	urlStr := "httppppp://example.com"

	_, err := requestWithHeader(http.MethodGet, urlStr, bytes.NewReader(bodyData), header, []byte{}, 0)
	execptedErrStr := "Get \"httppppp://example.com\": unsupported protocol scheme \"httppppp\""

	if err == nil || err.Error() != execptedErrStr {
		t.Errorf("Expected error: %s, got: %v", execptedErrStr, err)
  }
}
