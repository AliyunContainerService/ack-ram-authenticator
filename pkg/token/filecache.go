package token

import (
	"context"
	"github.com/alibabacloud-go/tea/tea"
)

type FileCacheCredential struct {
	provider *FileCacheProvider
}

func (r *FileCacheCredential) GetAccessKeyId() (*string, error) {
	cred, err := r.provider.GetCredential(context.TODO())
	if err != nil {
		return nil, err
	}
	return tea.String(cred.AccessKeyId), nil
}

func (r *FileCacheCredential) GetAccessKeySecret() (*string, error) {
	cred, err := r.provider.GetCredential(context.TODO())
	if err != nil {
		return nil, err
	}
	return tea.String(cred.AccessKeySecret), nil
}

func (r *FileCacheCredential) GetSecurityToken() (*string, error) {
	cred, err := r.provider.GetCredential(context.TODO())
	if err != nil {
		return nil, err
	}
	return tea.String(cred.SecurityToken), nil
}

func (r *FileCacheCredential) GetBearerToken() *string {
	return tea.String("")
}

func (r *FileCacheCredential) GetType() *string {
	return tea.String("ack_filecache_token")
}
