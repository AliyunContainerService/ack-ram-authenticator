package token

import (
	"fmt"
	"strings"
	"testing"
)

// TestNewOpenAPIErr tests the newOpenAPIErr function with various status codes and error messages.
func TestNewOpenAPIErr(t *testing.T) {
	internalServerError := "Internal Server Error"
	badRequest := "Bad Request"
	ok := "OK"

	// Test case 1: Status code 500, empty response code
	body1 := []byte{}
	rawErr1 := fmt.Errorf("raw error 1")
	stsErr1 := newOpenAPIErr(500, body1, rawErr1)
	if !stsErr1.RaiseToUser() || !strings.Contains(stsErr1.message, internalServerError) {
		t.Errorf("Unexpected result for status code 500: %+v", stsErr1)
	}

	// Test case 2: Status code 400, specific response code
	respBody2 := []byte(`{"Code": "InvalidAccessKeyId.Inactive"}`)
	rawErr2 := fmt.Errorf("raw error 2")
	stsErr2 := newOpenAPIErr(400, respBody2, rawErr2)
	if !stsErr2.RaiseToUser() || !strings.Contains(stsErr2.message, badRequest) || !strings.Contains(stsErr2.message, "InvalidAccessKeyId.Inactive") {
		t.Errorf("Unexpected result for status code 400: %+v", stsErr2)
	}

	// Test case 3: Status code 200, non-empty request ID
	respBody3 := []byte(`{"RequestId": "requestID123"}`)
	stsErr3 := newOpenAPIErr(200, respBody3, nil)
	if !stsErr3.RaiseToUser() || !strings.Contains(stsErr3.message, ok) || !strings.Contains(stsErr3.message, "requestID123") {
		t.Errorf("Unexpected result for status code 200: %+v", stsErr3)
	}

	// Test case 4: Status code 400, unknown response code
	respBody4 := []byte(`{"Code": "UnknownError"}`)
	stsErr4 := newOpenAPIErr(400, respBody4, nil)
	if !stsErr4.RaiseToUser() || !strings.Contains(stsErr4.message, badRequest) {
		t.Errorf("Unexpected result for status code 400: %+v", stsErr4)
	}

	// Test case 5: Status code 500, non-empty response code
	respBody5 := []byte(`{"Code": "InternalServerError", "Message": "Server Error"}`)
	stsErr5 := newOpenAPIErr(500, respBody5, nil)
	if !stsErr5.RaiseToUser() || !strings.Contains(stsErr5.message, internalServerError) {
		t.Errorf("Unexpected result for status code 500: %+v", stsErr5)
	}
}
