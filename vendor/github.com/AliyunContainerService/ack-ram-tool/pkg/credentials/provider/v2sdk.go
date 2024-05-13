package provider

import (
	"context"
)

type CredentialForV2SDK struct {
	p      CredentialsProvider
	Logger Logger
}

type CredentialForV2SDKOptions struct {
	Logger Logger
}

func NewCredentialForV2SDK(p CredentialsProvider, opts CredentialForV2SDKOptions) *CredentialForV2SDK {
	opts.applyDefaults()

	return &CredentialForV2SDK{
		p:      p,
		Logger: opts.Logger,
	}
}

func (c *CredentialForV2SDK) GetAccessKeyId() (*string, error) {
	cred, err := c.p.Credentials(context.TODO())
	if err != nil {
		return nil, err
	}
	return stringPointer(cred.AccessKeyId), nil
}

func (c *CredentialForV2SDK) GetAccessKeySecret() (*string, error) {
	cred, err := c.p.Credentials(context.TODO())
	if err != nil {
		return nil, err
	}
	return stringPointer(cred.AccessKeySecret), nil
}

func (c *CredentialForV2SDK) GetSecurityToken() (*string, error) {
	cred, err := c.p.Credentials(context.TODO())
	if err != nil {
		return nil, err
	}
	return stringPointer(cred.SecurityToken), nil
}

func (c *CredentialForV2SDK) GetBearerToken() *string {
	return stringPointer("")
}

func (c *CredentialForV2SDK) GetType() *string {
	return stringPointer("CredentialForV2SDK")
}

func (c *CredentialForV2SDK) logger() Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return defaultLog
}

func (o *CredentialForV2SDKOptions) applyDefaults() {
	if o.Logger == nil {
		o.Logger = defaultLog
	}
}

func stringPointer(s string) *string {
	return &s
}
