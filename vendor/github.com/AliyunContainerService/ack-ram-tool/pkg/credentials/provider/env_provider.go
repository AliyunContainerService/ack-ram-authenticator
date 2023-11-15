package provider

import (
	"context"
	"fmt"
	"os"
)

const (
	envAccessKeyId     = "ALIBABA_CLOUD_ACCESS_KEY_ID"
	envAccessKeySecret = "ALIBABA_CLOUD_ACCESS_KEY_SECRET"
	envSecurityToken   = "ALIBABA_CLOUD_SECURITY_TOKEN"
)

type EnvProvider struct {
	cp *ChainProvider
}

type EnvProviderOptions struct {
	EnvAccessKeyId     string
	EnvAccessKeySecret string
	EnvSecurityToken   string

	EnvRoleArn         string
	EnvOIDCProviderArn string
	EnvOIDCTokenFile   string
}

func NewEnvProvider(opts EnvProviderOptions) *EnvProvider {
	opts.applyDefaults()

	e := &EnvProvider{}
	e.cp = e.getProvider(opts)

	return e
}

func (e *EnvProvider) Credentials(ctx context.Context) (*Credentials, error) {
	cred, err := e.cp.Credentials(ctx)

	if err != nil {
		if IsNoAvailableProviderError(err) {
			return nil, NewNotEnableError(fmt.Errorf("not found credentials from env: %w", err))
		}
		return nil, err
	}

	return cred.DeepCopy(), nil
}

func (e *EnvProvider) getProvider(opts EnvProviderOptions) *ChainProvider {
	p1 := NewSTSTokenProvider(
		os.Getenv(opts.EnvAccessKeyId),
		os.Getenv(opts.EnvAccessKeySecret),
		os.Getenv(opts.EnvSecurityToken),
	)
	p2 := NewOIDCProvider(OIDCProviderOptions{
		RoleArn:         os.Getenv(opts.EnvRoleArn),
		OIDCProviderArn: os.Getenv(opts.EnvOIDCProviderArn),
		OIDCTokenFile:   os.Getenv(opts.EnvOIDCTokenFile),
	})
	p3 := NewAccessKeyProvider(
		os.Getenv(opts.EnvAccessKeyId),
		os.Getenv(opts.EnvAccessKeySecret),
	)
	cp := NewChainProvider(p1, p2, p3)
	return cp
}

func (o *EnvProviderOptions) applyDefaults() {
	if o.EnvAccessKeyId == "" {
		o.EnvAccessKeyId = envAccessKeyId
	}
	if o.EnvAccessKeySecret == "" {
		o.EnvAccessKeySecret = envAccessKeySecret
	}
	if o.EnvSecurityToken == "" {
		o.EnvSecurityToken = envSecurityToken
	}

	if o.EnvRoleArn == "" {
		o.EnvRoleArn = defaultEnvRoleArn
	}
	if o.EnvOIDCProviderArn == "" {
		o.EnvOIDCProviderArn = defaultEnvOIDCProviderArn
	}
	if o.EnvOIDCTokenFile == "" {
		o.EnvOIDCTokenFile = defaultEnvOIDCTokenFile
	}
}
