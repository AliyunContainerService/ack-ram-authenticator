package file

import (
	"reflect"
	"testing"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
)

func TestFileMapper_Map(t *testing.T) {
	type args struct {
		canonicalARN string
	}
	tests := []struct {
		name    string
		m       *FileMapper
		args    args
		want    *config.IdentityMapping
		wantErr string
	}{
		{
			name: "testNotMapped",
			m:    &FileMapper{},
			args: args{
				canonicalARN: "test",
			},
			want:    nil,
			wantErr: "ARN is not mapped",
		},
		{
			name: "testRole",
			m: &FileMapper{
				roleMap: map[string]config.RoleMapping{
					"test": {
						RoleARN:  "aa",
						Username: "aa",
						Groups:   []string{"aa"},
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
			m: &FileMapper{
				userMap: map[string]config.UserMapping{
					"test": {
						UserARN:  "bb",
						Username: "bb",
						Groups:   []string{"bb"},
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
			if (err != nil) && err.Error() != tt.wantErr {
				t.Errorf("FileMapper.Map() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FileMapper.Map() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewFileMapper(t *testing.T) {
	type args struct {
		cfg config.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *FileMapper
		wantErr string
	}{
		{
			name: "testNilRoleMappings",
			args: args{
				cfg: config.Config{
					RoleMappings: []config.RoleMapping{
						{
							RoleARN: "",
						},
					},
				},
			},
			want:    nil,
			wantErr: "One of rolearn must be supplied",
		},
		{
			name: "testNilUserMappings",
			args: args{
				cfg: config.Config{
					RoleMappings: []config.RoleMapping{
						{
							RoleARN: "aa",
						},
					},
					UserMappings: []config.UserMapping{
						{
							UserARN: "",
						},
					},
				},
			},
			want:    nil,
			wantErr: "Value for userarn must be supplied",
		},
		{
			name: "testErrorCanonicalizeARN",
			args: args{
				cfg: config.Config{
					RoleMappings: []config.RoleMapping{
						{
							RoleARN: "aa",
						},
					},
					UserMappings: []config.UserMapping{
						{
							UserARN: "bb",
						},
					},
				},
			},
			want:    nil,
			wantErr: "error canonicalizing ARN: arn 'bb' is invalid: 'acs: invalid prefix'",
		},
		{
			name: "testErrorCanonicalizeARN",
			args: args{
				cfg: config.Config{
					RoleMappings: []config.RoleMapping{
						{
							RoleARN: "aa",
						},
					},
					UserMappings: []config.UserMapping{
						{
							UserARN: "acs:ram::1234567890:user/bb",
						},
					},
					AutoMappedAlibabaCloudAccounts: []string{
						"bb",
					},
				},
			},
			want: &FileMapper{
				roleMap: map[string]config.RoleMapping{
					"aa": {
						RoleARN: "aa",
					},
				},
				userMap: map[string]config.UserMapping{
					"acs:ram::1234567890:user/bb": {
						UserARN: "acs:ram::1234567890:user/bb",
					},
				},
				accountMap: map[string]bool{
					"bb": true,
				},
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFileMapper(tt.args.cfg)
			if (err != nil) && err.Error() != tt.wantErr {
				t.Errorf("NewFileMapper() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewFileMapper() = %v, want %v", got, tt.want)
			}
		})
	}
}
