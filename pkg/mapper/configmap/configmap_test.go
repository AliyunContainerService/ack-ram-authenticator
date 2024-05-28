package configmap

import (
	"errors"
	"reflect"
	"testing"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
)

func TestParseMap(t *testing.T) {
	type args struct {
		m map[string]string
	}
	tests := []struct {
		name                     string
		args                     args
		wantUserMappings         []config.UserMapping
		wantRoleMappings         []config.RoleMapping
		wantAlibabaCloudAccounts []string
		wantErr                  bool
	}{
		{
			name: "testSuccess",
			args: args{
				m: map[string]string{
					"mapUsers": `- userarn: aa
  username: aa
  groups:
  - aa
`,
					"mapRoles": `- rolearn: bb
  username: bb
  groups:
  - bb
`,
					"mapAccounts": `- cc
`,
				},
			},
			wantUserMappings: []config.UserMapping{
				{
					UserARN:  "aa",
					Username: "aa",
					Groups:   []string{"aa"},
				},
			},
			wantRoleMappings: []config.RoleMapping{
				{
					RoleARN:  "bb",
					Username: "bb",
					Groups:   []string{"bb"},
				},
			},
			wantAlibabaCloudAccounts: []string{"cc"},
			wantErr:                  false,
		},
		{
			name: "testUserFailed",
			args: args{
				m: map[string]string{
					"mapUsers": `userrn aa
  userame aa
  grous
  - aa
`,
				},
			},
			wantUserMappings:         make([]config.UserMapping, 0),
			wantRoleMappings:         make([]config.RoleMapping, 0),
			wantAlibabaCloudAccounts: make([]string, 0),
			wantErr:                  true,
		},
		{
			name: "testRoleFailed",
			args: args{
				m: map[string]string{
					"mapRoles": `rolearn aa
  userame aa
  grous
  - aa
`,
				},
			},
			wantUserMappings:         make([]config.UserMapping, 0),
			wantRoleMappings:         make([]config.RoleMapping, 0),
			wantAlibabaCloudAccounts: make([]string, 0),
			wantErr:                  true,
		},
		{
			name: "testAccountFailed",
			args: args{
				m: map[string]string{
					"mapAccounts": `c
`,
				},
			},
			wantUserMappings:         make([]config.UserMapping, 0),
			wantRoleMappings:         make([]config.RoleMapping, 0),
			wantAlibabaCloudAccounts: make([]string, 0),
			wantErr:                  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserMappings, gotRoleMappings, gotAlibabaCloudAccounts, err := ParseMap(tt.args.m)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUserMappings, tt.wantUserMappings) {
				t.Errorf("ParseMap() gotUserMappings = %v, want %v", gotUserMappings, tt.wantUserMappings)
			}
			if !reflect.DeepEqual(gotRoleMappings, tt.wantRoleMappings) {
				t.Errorf("ParseMap() gotRoleMappings = %v, want %v", gotRoleMappings, tt.wantRoleMappings)
			}
			if !reflect.DeepEqual(gotAlibabaCloudAccounts, tt.wantAlibabaCloudAccounts) {
				t.Errorf("ParseMap() gotAlibabaCloudAccounts = %v, want %v", gotAlibabaCloudAccounts, tt.wantAlibabaCloudAccounts)
			}
		})
	}
}

func TestEncodeMap(t *testing.T) {
	type args struct {
		userMappings         []config.UserMapping
		roleMappings         []config.RoleMapping
		alibabaCloudAccounts []string
	}
	tests := []struct {
		name    string
		args    args
		wantM   map[string]string
		wantErr bool
	}{
		{
			name: "testSuccess",
			args: args{
				userMappings: []config.UserMapping{
					{
						UserARN:  "aa",
						Username: "aa",
						Groups:   []string{"aa"},
					},
				},
				roleMappings: []config.RoleMapping{
					{
						RoleARN:  "bb",
						Username: "bb",
						Groups:   []string{"bb"},
					},
				},
				alibabaCloudAccounts: []string{"cc"},
			},
			wantM: map[string]string{
				"mapUsers": `- userarn: aa
  username: aa
  groups:
  - aa
`,
				"mapRoles": `- rolearn: bb
  username: bb
  groups:
  - bb
`,
				"mapAccounts": `- cc
`,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotM, err := EncodeMap(tt.args.userMappings, tt.args.roleMappings, tt.args.alibabaCloudAccounts)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotM, tt.wantM) {
				t.Errorf("EncodeMap() = %v, want %v", gotM, tt.wantM)
			}
		})
	}
}

func TestMapStore_UserMapping(t *testing.T) {
	type args struct {
		arn string
	}
	tests := []struct {
		name    string
		ms      *MapStore
		args    args
		want    config.UserMapping
		wantErr error
	}{
		{
			name: "testNotFound",
			ms:   &MapStore{},
			args: args{
				arn: "test",
			},
			want:    config.UserMapping{},
			wantErr: errors.New("User not found in configmap"),
		},
		{
			name: "testSuccess",
			ms: &MapStore{
				users: map[string]config.UserMapping{
					"test": {
						UserARN: "test",
					},
				},
			},
			args: args{
				arn: "test",
			},
			want: config.UserMapping{
				UserARN: "test",
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ms.UserMapping(tt.args.arn)
			if err != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("MapStore.UserMapping() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapStore.UserMapping() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapStore_RoleMapping(t *testing.T) {
	type args struct {
		arn string
	}
	tests := []struct {
		name    string
		ms      *MapStore
		args    args
		want    config.RoleMapping
		wantErr error
	}{
		{
			name: "testNotFound",
			ms:   &MapStore{},
			args: args{
				arn: "test",
			},
			want:    config.RoleMapping{},
			wantErr: errors.New("Role not found in configmap"),
		},
		{
			name: "testSuccess",
			ms: &MapStore{
				roles: map[string]config.RoleMapping{
					"test": {
						RoleARN: "test",
					},
				},
			},
			args: args{
				arn: "test",
			},
			want: config.RoleMapping{
				RoleARN: "test",
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ms.RoleMapping(tt.args.arn)
			if err != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("MapStore.RoleMapping() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapStore.RoleMapping() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapStore_AlibabaCloudAccount(t *testing.T) {
	type args struct {
		id string
	}
	tests := []struct {
		name string
		ms   *MapStore
		args args
		want bool
	}{
		{
			name: "testFalse",
			ms: &MapStore{
				alibabaCloudAccounts: nil,
			},
			args: args{
				id: "test",
			},
			want: false,
		},
		{
			name: "testTrue",
			ms: &MapStore{
				alibabaCloudAccounts: map[string]interface{}{
					"test": nil,
				},
			},
			args: args{
				id: "test",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ms.AlibabaCloudAccount(tt.args.id); got != tt.want {
				t.Errorf("MapStore.AlibabaCloudAccount() = %v, want %v", got, tt.want)
			}
		})
	}
}
