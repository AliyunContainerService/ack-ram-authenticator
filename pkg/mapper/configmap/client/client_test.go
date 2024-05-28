// Package client implements client-side operations on auth configmap.
package client

import (
	"errors"
	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
	core_v1 "k8s.io/api/core/v1"
	"reflect"
	"testing"
)

func Test_client_add(t *testing.T) {
	type args struct {
		role *config.RoleMapping
		user *config.UserMapping
	}
	tests := []struct {
		name    string
		cli     *client
		args    args
		wantCm  *core_v1.ConfigMap
		wantErr string
	}{
		{
			name: "testEmpty",
			cli:  &client{},
			args: args{
				role: nil,
				user: nil,
			},
			wantCm:  nil,
			wantErr: "empty role/user",
		},
		{
			name: "testGetMapError",
			cli: &client{
				getMap: func() (*core_v1.ConfigMap, error) {
					return nil, errors.New("get err")
				},
			},
			args: args{
				role: &config.RoleMapping{},
				user: &config.UserMapping{},
			},
			wantCm:  nil,
			wantErr: "get err",
		},
		{
			name: "testParseFailed",
			cli: &client{
				getMap: func() (*core_v1.ConfigMap, error) {
					return &core_v1.ConfigMap{
						Data: map[string]string{
							"mapRoles": "rolearn:aa",
						},
					}, nil
				},
			},
			args: args{
				role: &config.RoleMapping{
					RoleARN: "aa",
				},
				user: &config.UserMapping{},
			},
			wantCm: &core_v1.ConfigMap{
				Data: map[string]string{
					"mapRoles": "rolearn:aa",
				},
			},
			wantErr: "failed to parse configmap error parsing config map: [json: cannot unmarshal string into Go value of type []config.RoleMapping]",
		},
		{
			name: "testRoleIsInvalid",
			cli: &client{
				getMap: func() (*core_v1.ConfigMap, error) {
					return &core_v1.ConfigMap{}, nil
				},
			},
			args: args{
				role: &config.RoleMapping{},
				user: &config.UserMapping{},
			},
			wantCm:  &core_v1.ConfigMap{},
			wantErr: "role is invalid: One of rolearn must be supplied",
		},
		{
			name: "testDuplicateRole",
			cli: &client{
				getMap: func() (*core_v1.ConfigMap, error) {
					return &core_v1.ConfigMap{
						Data: map[string]string{
							"mapRoles": "[{\"rolearn\":\"aa\"}]",
						},
					}, nil
				},
			},
			args: args{
				role: &config.RoleMapping{
					RoleARN: "aa",
				},
				user: &config.UserMapping{},
			},
			wantCm: &core_v1.ConfigMap{
				Data: map[string]string{
					"mapRoles": "[{\"rolearn\":\"aa\"}]",
				},
			},
			wantErr: "cannot add duplicate role ARN \"aa\"",
		},
		{
			name: "testUserIsInvalid",
			cli: &client{
				getMap: func() (*core_v1.ConfigMap, error) {
					return &core_v1.ConfigMap{}, nil
				},
			},
			args: args{
				role: &config.RoleMapping{
					RoleARN: "aa",
				},
				user: &config.UserMapping{},
			},
			wantCm:  &core_v1.ConfigMap{},
			wantErr: "user is invalid: Value for userarn must be supplied",
		},
		{
			name: "testDuplicateUser",
			cli: &client{
				getMap: func() (*core_v1.ConfigMap, error) {
					return &core_v1.ConfigMap{
						Data: map[string]string{
							"mapUsers": "[{\"userarn\":\"aa\"}]",
						},
					}, nil
				},
			},
			args: args{
				role: &config.RoleMapping{
					RoleARN: "aa",
				},
				user: &config.UserMapping{
					UserARN: "aa",
				},
			},
			wantCm: &core_v1.ConfigMap{
				Data: map[string]string{
					"mapUsers": "[{\"userarn\":\"aa\"}]",
				},
			},
			wantErr: "cannot add duplicate user ARN \"aa\"",
		},
		{
			name: "testUpdateMapError",
			cli: &client{
				getMap: func() (*core_v1.ConfigMap, error) {
					return &core_v1.ConfigMap{}, nil
				},
				updateMap: func(m *core_v1.ConfigMap) (cm *core_v1.ConfigMap, err error) {
					return nil, errors.New("update error")
				},
			},
			args: args{
				role: &config.RoleMapping{
					RoleARN: "aa",
				},
				user: &config.UserMapping{
					UserARN: "aa",
				},
			},
			wantCm: &core_v1.ConfigMap{
				Data: map[string]string{
					"mapRoles": `- rolearn: aa
  username: ""
  groups: []
`,
					"mapUsers": `- userarn: aa
  username: ""
  groups: []
`,
				},
			},
			wantErr: "update error",
		},
		{
			name: "testSuccess",
			cli: &client{
				getMap: func() (*core_v1.ConfigMap, error) {
					return &core_v1.ConfigMap{}, nil
				},
				updateMap: func(m *core_v1.ConfigMap) (cm *core_v1.ConfigMap, err error) {
					return &core_v1.ConfigMap{}, nil
				},
			},
			args: args{
				role: &config.RoleMapping{
					RoleARN: "aa",
				},
				user: &config.UserMapping{
					UserARN: "aa",
				},
			},
			wantCm: &core_v1.ConfigMap{},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCm, err := tt.cli.add(tt.args.role, tt.args.user)
			if err != nil && err.Error() != tt.wantErr {
				t.Errorf("client.add() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCm, tt.wantCm) {
				t.Errorf("client.add() = %v, want %v", gotCm, tt.wantCm)
			}
		})
	}
}
