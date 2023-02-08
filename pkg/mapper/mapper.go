package mapper

import (
	"errors"
	"fmt"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	// Deprecated: use ModeMountedFile instead
	ModeFile string = "File"
	// Deprecated: use ModeACKConfigMap instead
	ModeConfigMap string = "ConfigMap"

	ModeMountedFile string = "MountedFile"

	ModeACKConfigMap string = "ACKConfigMap"

	ModeCRD string = "CRD"

	ModeDynamicFile string = "DynamicFile"
)

var (
	ValidBackendModeChoices      = []string{ModeFile, ModeConfigMap, ModeMountedFile, ModeACKConfigMap, ModeCRD, ModeDynamicFile}
	DeprecatedBackendModeChoices = map[string]string{
		ModeFile:      ModeMountedFile,
		ModeConfigMap: ModeACKConfigMap,
	}
	BackendModeChoices = []string{ModeMountedFile, ModeACKConfigMap, ModeCRD, ModeDynamicFile}
)

var ErrNotMapped = errors.New("ARN is not mapped")

type Mapper interface {
	Name() string
	// Start must be non-blocking
	Start(stopCh <-chan struct{}) error
	Map(canonicalARN string) (*config.IdentityMapping, error)
	IsAccountAllowed(accountID string) bool
}

func ValidateBackendMode(modes []string) []error {
	var errs []error

	validModes := sets.NewString(ValidBackendModeChoices...)
	for _, mode := range modes {
		if !validModes.Has(mode) {
			errs = append(errs, fmt.Errorf("backend-mode %q is not a valid mode", mode))
		}
	}

	for _, mode := range modes {
		if replacementMode, ok := DeprecatedBackendModeChoices[mode]; ok {
			logrus.Warningf("warning: backend-mode %q is deprecated, use %q instead", mode, replacementMode)
		}
	}

	if len(modes) != sets.NewString(modes...).Len() {
		errs = append(errs, fmt.Errorf("backend-mode %q has duplicates", modes))
	}

	if len(modes) == 0 {
		errs = append(errs, fmt.Errorf("at least one backend-mode must be specified"))
	}

	return errs
}
