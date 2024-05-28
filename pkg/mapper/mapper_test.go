package mapper

import (
	"fmt"
	"reflect"
	"testing"
)

func TestValidateBackendMode(t *testing.T) {
	type args struct {
		modes []string
	}
	tests := []struct {
		name string
		args args
		want []error
	}{
		{
			"testEmptyMode",
			args{
				modes: nil,
			},
			[]error{
				fmt.Errorf("at least one backend-mode must be specified"),
			},
		},

		{
			"testInvalidMode",
			args{
				modes: []string{
					"test",
				},
			},
			[]error{
				fmt.Errorf("backend-mode \"test\" is not a valid mode"),
			},
		},

		{
			"testDuplicateMode",
			args{
				modes: []string{
					"ConfigMap",
					"ConfigMap",
				},
			},
			[]error{
				fmt.Errorf("backend-mode %q has duplicates", []string{"ConfigMap", "ConfigMap"}),
			},
		},

		{
			"testValidMode",
			args{
				modes: []string{
					"ConfigMap",
				},
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateBackendMode(tt.args.modes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateBackendMode() = %v, want %v", got, tt.want)
			}
		})
	}
}
