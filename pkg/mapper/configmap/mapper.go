package configmap

import (
	"strings"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/mapper"
)

type ConfigMapMapper struct {
	*MapStore
}

var _ mapper.Mapper = &ConfigMapMapper{}

func NewConfigMapMapper(cfg config.Config) (*ConfigMapMapper, error) {
	ms, err := New(cfg.Master, cfg.Kubeconfig)
	if err != nil {
		return nil, err
	}
	return &ConfigMapMapper{ms}, nil
}

func (m *ConfigMapMapper) Name() string {
	return mapper.ModeACKConfigMap
}

func (m *ConfigMapMapper) Start(stopCh <-chan struct{}) error {
	m.startLoadConfigMap(stopCh)
	return nil
}

func (m *ConfigMapMapper) Map(canonicalARN string) (*config.IdentityMapping, error) {
	canonicalARN = strings.ToLower(canonicalARN)

	rm, err := m.RoleMapping(canonicalARN)
	// TODO: Check for non Role/UserNotFound errors
	if err == nil {
		return &config.IdentityMapping{
			IdentityARN: canonicalARN,
			Username:    rm.Username,
			Groups:      rm.Groups,
		}, nil
	}

	um, err := m.UserMapping(canonicalARN)
	if err == nil {
		return &config.IdentityMapping{
			IdentityARN: canonicalARN,
			Username:    um.Username,
			Groups:      um.Groups,
		}, nil
	}

	return nil, mapper.ErrNotMapped
}

func (m *ConfigMapMapper) IsAccountAllowed(accountID string) bool {
	return m.AWSAccount(accountID)
}
