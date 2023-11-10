package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultSTSEndpoint = "sts.aliyuncs.com"
	defaultSTSScheme   = "HTTPS"

	defaultEnvRoleArn         = "ALIBABA_CLOUD_ROLE_ARN"
	defaultEnvOIDCProviderArn = "ALIBABA_CLOUD_OIDC_PROVIDER_ARN"
	defaultEnvOIDCTokenFile   = "ALIBABA_CLOUD_OIDC_TOKEN_FILE"

	defaultExpiryWindowForAssumeRole = time.Minute * 10
)

var defaultSessionName = "default-session-name"

type OIDCProvider struct {
	u *Updater

	client *http.Client

	stsEndpoint string
	stsScheme   string
	sessionName string

	roleArn         string
	oidcProviderArn string
	oidcTokenFile   string

	Logger Logger
}

type OIDCProviderOptions struct {
	STSEndpoint string
	stsScheme   string
	SessionName string

	RoleArn            string
	EnvRoleArn         string
	OIDCProviderArn    string
	EnvOIDCProviderArn string
	OIDCTokenFile      string
	EnvOIDCTokenFile   string

	Timeout   time.Duration
	Transport http.RoundTripper

	ExpiryWindow  time.Duration
	RefreshPeriod time.Duration
	Logger        Logger
}

func init() {
	sessionName := getRoleSessionNameFromEnv()
	if sessionName != "" {
		defaultSessionName = sessionName
	}
}

func NewOIDCProvider(opts OIDCProviderOptions) *OIDCProvider {
	opts.applyDefaults()

	client := &http.Client{
		Transport: opts.Transport,
		Timeout:   opts.Timeout,
	}
	e := &OIDCProvider{
		client:          client,
		stsEndpoint:     opts.STSEndpoint,
		stsScheme:       opts.stsScheme,
		sessionName:     opts.SessionName,
		roleArn:         opts.getRoleArn(),
		oidcProviderArn: opts.getOIDCProviderArn(),
		oidcTokenFile:   opts.getOIDCTokenFile(),
		Logger:          opts.Logger,
	}
	e.u = NewUpdater(e.getCredentials, UpdaterOptions{
		ExpiryWindow:  opts.ExpiryWindow,
		RefreshPeriod: opts.RefreshPeriod,
		Logger:        opts.Logger,
		LogPrefix:     "[OIDCProvider]",
	})
	e.u.Start(context.TODO())

	return e
}

func (o *OIDCProvider) Credentials(ctx context.Context) (*Credentials, error) {
	return o.u.Credentials(ctx)
}

func (o *OIDCProvider) Stop(ctx context.Context) {
	o.u.Stop(ctx)
}

func (o *OIDCProvider) getCredentials(ctx context.Context) (*Credentials, error) {
	roleArn := o.roleArn
	oidcProviderArn := o.oidcProviderArn
	tokenFile := o.oidcTokenFile
	if roleArn == "" || oidcProviderArn == "" || tokenFile == "" {
		return nil, NewNotEnableError(errors.New("roleArn, oidcProviderArn or oidcTokenFile is empty"))
	}

	tokenData, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}
	token := string(tokenData)
	return o.assumeRoleWithOIDC(ctx, roleArn, oidcProviderArn, token)
}

type oidcResponse struct {
	Credentials *credentialsInResponse `json:"Credentials"`
}

type credentialsInResponse struct {
	AccessKeyId     string `json:"AccessKeyId"`
	AccessKeySecret string `json:"AccessKeySecret"`
	SecurityToken   string `json:"SecurityToken"`
	Expiration      string `json:"Expiration"`
}

func (o *OIDCProvider) assumeRoleWithOIDC(ctx context.Context, roleArn, oidcProviderArn, token string) (*Credentials, error) {
	reqOpts := newCommonRequest()
	reqOpts.Domain = o.stsEndpoint
	reqOpts.Scheme = o.stsScheme
	reqOpts.Method = "POST"
	reqOpts.QueryParams["Timestamp"] = getTimeInFormatISO8601()
	reqOpts.QueryParams["Action"] = "AssumeRoleWithOIDC"
	reqOpts.QueryParams["Format"] = "JSON"
	reqOpts.QueryParams["RoleArn"] = roleArn
	reqOpts.QueryParams["OIDCProviderArn"] = oidcProviderArn
	reqOpts.BodyParams["OIDCToken"] = token
	//reqOpts.QueryParams["Policy"] = policy
	reqOpts.QueryParams["RoleSessionName"] = o.sessionName
	reqOpts.QueryParams["Version"] = "2015-04-01"
	reqOpts.QueryParams["SignatureNonce"] = getUUID()
	reqOpts.Headers["Accept-Encoding"] = "identity"
	reqOpts.Headers["content-type"] = "application/x-www-form-urlencoded"
	reqOpts.URL = reqOpts.BuildURL()

	req, err := http.NewRequest(reqOpts.Method, reqOpts.URL, strings.NewReader(getURLFormedMap(reqOpts.BodyParams)))
	if err != nil {
		return nil, err
	}
	for k, v := range reqOpts.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", UserAgent)
	req = req.WithContext(ctx)

	if debugMode {
		for _, item := range genDebugReqMessages(req) {
			o.logger().Debug(item)
		}
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %w", req.URL, err)
	}
	defer resp.Body.Close()

	if debugMode {
		for _, item := range genDebugRespMessages(resp) {
			o.logger().Debug(item)
		}
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var obj oidcResponse
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	if obj.Credentials == nil || obj.Credentials.AccessKeySecret == "" {
		return nil, fmt.Errorf("call AssumeRoleWithOIDC failed, got unexpected body: %s",
			strings.ReplaceAll(string(data), "\n", " "))
	}

	exp, err := time.Parse("2006-01-02T15:04:05Z", obj.Credentials.Expiration)
	if err != nil {
		return nil, err
	}
	return &Credentials{
		AccessKeyId:     obj.Credentials.AccessKeyId,
		AccessKeySecret: obj.Credentials.AccessKeySecret,
		SecurityToken:   obj.Credentials.SecurityToken,
		Expiration:      exp,
	}, nil
}

func (o *OIDCProvider) logger() Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return defaultLog
}

func (o *OIDCProviderOptions) applyDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = defaultClientTimeout
	}
	if o.Transport == nil {
		ts := http.DefaultTransport.(*http.Transport).Clone()
		o.Transport = ts
	}
	if o.STSEndpoint == "" {
		o.STSEndpoint = defaultSTSEndpoint
	} else {
		o.STSEndpoint = strings.TrimRight(o.STSEndpoint, "/")
	}

	if strings.HasPrefix(o.STSEndpoint, "https://") {
		o.stsScheme = "HTTPS"
		o.STSEndpoint = strings.TrimPrefix(o.STSEndpoint, "https://")
	} else if strings.HasPrefix(o.STSEndpoint, "http://") {
		o.stsScheme = "HTTP"
		o.STSEndpoint = strings.TrimPrefix(o.STSEndpoint, "http://")
	}
	if o.stsScheme == "" {
		o.stsScheme = defaultSTSScheme
	}
	o.stsScheme = strings.ToUpper(o.stsScheme)

	if o.SessionName == "" {
		o.SessionName = defaultSessionName
	}
	if o.ExpiryWindow == 0 {
		o.ExpiryWindow = defaultExpiryWindowForAssumeRole
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
	if o.Logger == nil {
		o.Logger = defaultLog
	}
}

func (o *OIDCProviderOptions) getRoleArn() string {
	if o.RoleArn != "" {
		return o.RoleArn
	}
	return os.Getenv(o.EnvRoleArn)
}

func (o *OIDCProviderOptions) getOIDCProviderArn() string {
	if o.OIDCProviderArn != "" {
		return o.OIDCProviderArn
	}
	return os.Getenv(o.EnvOIDCProviderArn)
}

func (o *OIDCProviderOptions) getOIDCTokenFile() string {
	if o.OIDCTokenFile != "" {
		return o.OIDCTokenFile
	}
	return os.Getenv(o.EnvOIDCTokenFile)
}
