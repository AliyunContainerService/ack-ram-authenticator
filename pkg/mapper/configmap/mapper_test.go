package configmap

import (
	"reflect"
	"testing"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
)

func TestConfigMapMapper_Map(t *testing.T) {
	type args struct {
		canonicalARN string
	}
	tests := []struct {
		name    string
		m       *ConfigMapMapper
		args    args
		want    *config.IdentityMapping
		wantErr string
	}{
		{
			name: "testNotMapped",
			m:    &ConfigMapMapper{
				&MapStore{},
			},
			args: args{
				canonicalARN: "test",
			},
			want:    nil,
			wantErr: "ARN is not mapped",
		},
		{
			name: "testRole",
			m: &ConfigMapMapper{
				&MapStore{
					roles: map[string]config.RoleMapping {
						"test": {
							RoleARN: "aa",
							Username: "aa",
							Groups: []string{"aa"},
						},
					},
				},
			},
			args: args{
				canonicalARN: "aa",
			},
			want: &config.IdentityMapping{
				IdentityARN: "aa",
				Username:    "aa",
				Groups:      []string{"aa"},
			},
			wantErr: "",
		},
		{
			name: "testUser",
			m: &ConfigMapMapper{
				&MapStore{
					users: map[string]config.UserMapping{
						"test": {
							UserARN: "bb",
							Username: "bb",
							Groups: []string{"bb"},
						},
					},
				},
			},
			args: args{
				canonicalARN: "bb",
			},
			want: &config.IdentityMapping{
				IdentityARN: "bb",
				Username:    "bb",
				Groups:      []string{"bb"},
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.Map(tt.args.canonicalARN)
			if err != nil && err.Error() != tt.wantErr {
				t.Errorf("ConfigMapMapper.Map() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConfigMapMapper.Map() = %v, want %v", got, tt.want)
			}
		})
	}
}
