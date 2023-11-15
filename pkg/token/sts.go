package token

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type OpenAPIErrorResp struct {
	RequestId string `json:"RequestId,omitempty"`
	Message   string `json:"Message,omitempty"`
	Code      string `json:"Code"`
}

// https://aliyuque.antfin.com/alibabacloud-openapi/oz5vv9/kg9gn89a69uf2041
func newOpenAPIErr(statusCode int, body []byte, rawErr error) STSError {
	var resp OpenAPIErrorResp

	if len(body) > 0 {
		_ = json.Unmarshal(body, &resp)
	}
	stsErr := STSError{
		raiseToUser: true,
		message:     fmt.Sprintf("call sts.GetCallerIdentity failed: %s", http.StatusText(statusCode)),
	}
	if rawErr != nil && rawErr.Error() != "" {
		stsErr.message = fmt.Sprintf("%s, %s", stsErr.message, rawErr.Error())
	}

	var raiseCodeToUser bool
	switch {
	case statusCode >= 500 && resp.Code == "":
		raiseCodeToUser = true
		break
	case statusCode >= 400 && statusCode < 500:
		switch resp.Code {
		case "InvalidTimeStamp.Expired", "SignatureDoesNotMatch",
			"SignatureNonceUsed", "ContentMD5NotMatched",
			"InvalidSignatureMethod", "Throttling.User",
			"Throttling.Api", "MissingSecurityToken", "InvalidSecurityToken.Expired",
			"InvalidSecurityToken.MismatchWithAccessKey", "InvalidSecurityToken.Malformed",
			"InvalidAccessKeyId.Inactive", "InvalidAccessKeyId.NotFound":
			raiseCodeToUser = true
		}
		if strings.HasPrefix(resp.Code, "InvalidAccessKeyId.") ||
			strings.HasPrefix(resp.Code, "InvalidSecurityToken.") ||
			strings.HasPrefix(resp.Code, "Throttling.") {
			raiseCodeToUser = true
		}
		break
	case statusCode < 400:
		raiseCodeToUser = false
		if resp.RequestId != "" {
			stsErr.message = fmt.Sprintf("%s (RequestId: %s)", stsErr.message, resp.RequestId)
		}
	}

	if raiseCodeToUser && resp.Code != "" {
		stsErr.message = fmt.Sprintf("%s (RequestId: %s, Code: %s, Message: %s)",
			stsErr.message, resp.RequestId, resp.Code, resp.Message)
	}

	return stsErr
}
