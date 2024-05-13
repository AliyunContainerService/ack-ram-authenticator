package provider

import (
	"context"
	"fmt"
)

type SignerForV1SDK struct {
	p      CredentialsProvider
	Logger Logger
}

type SignerForV1SDKOptions struct {
	Logger Logger
}

func NewSignerForV1SDK(p CredentialsProvider, opts SignerForV1SDKOptions) *SignerForV1SDK {
	opts.applyDefaults()

	return &SignerForV1SDK{
		p:      p,
		Logger: opts.Logger,
	}
}

func (s *SignerForV1SDK) GetName() string {
	return "HMAC-SHA1"
}

func (s *SignerForV1SDK) GetType() string {
	return ""
}

func (s *SignerForV1SDK) GetVersion() string {
	return "1.0"
}

func (s *SignerForV1SDK) GetAccessKeyId() (string, error) {
	cred, err := s.p.Credentials(context.TODO())
	if err != nil {
		return "", err
	}
	return cred.AccessKeyId, nil
}

func (s *SignerForV1SDK) GetExtraParam() map[string]string {
	cred, err := s.p.Credentials(context.TODO())
	if err != nil {
		s.logger().Error(err, fmt.Sprintf("get credentials failed: %s", err))
		return nil
	}
	if cred.SecurityToken != "" {
		return map[string]string{"SecurityToken": cred.SecurityToken}
	}
	return nil
}

func (s *SignerForV1SDK) Sign(stringToSign, secretSuffix string) string {
	cred, err := s.p.Credentials(context.TODO())
	if err != nil {
		s.logger().Error(err, fmt.Sprintf("get credentials failed: %s", err))
		return ""
	}
	secret := cred.AccessKeySecret + secretSuffix
	return shaHmac1(stringToSign, secret)
}

func (s *SignerForV1SDK) logger() Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return defaultLog
}

func (o *SignerForV1SDKOptions) applyDefaults() {
	if o.Logger == nil {
		o.Logger = defaultLog
	}
}
