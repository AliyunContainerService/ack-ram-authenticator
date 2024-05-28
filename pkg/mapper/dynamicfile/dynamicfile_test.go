package dynamicfile

import (
	"os"
	"reflect"
	"testing"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
)

func TestParseMap_NoFile(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name             string
		args             args
		wantUserMappings []config.UserMapping
		wantRoleMappings []config.RoleMapping
		wantAliAccounts  []string
		wantErr          bool
	}{
		{
			name: "testNoFile",
			args: args{
				filename: "dynamicfile_test.yaml",
			},
			wantUserMappings: make([]config.UserMapping, 0),
			wantRoleMappings: make([]config.RoleMapping, 0),
			wantAliAccounts:  nil,
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserMappings, gotRoleMappings, gotAliAccounts, err := ParseMap(tt.args.filename)
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
			if !reflect.DeepEqual(gotAliAccounts, tt.wantAliAccounts) {
				t.Errorf("ParseMap() gotAliAccounts = %v, want %v", gotAliAccounts, tt.wantAliAccounts)
			}
		})
	}
}

func TestParseMap_EmptyFile(t *testing.T) {
	data := []byte("")
	err := os.WriteFile("dynamicfile_test.yaml", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file dynamicfile_test.yaml")
	}
	defer os.Remove("dynamicfile_test.yaml")

	type args struct {
		filename string
	}
	tests := []struct {
		name             string
		args             args
		wantUserMappings []config.UserMapping
		wantRoleMappings []config.RoleMapping
		wantAliAccounts  []string
		wantErr          bool
	}{
		{
			name: "testEmptyFile",
			args: args{
				filename: "dynamicfile_test.yaml",
			},
			wantUserMappings: make([]config.UserMapping, 0),
			wantRoleMappings: make([]config.RoleMapping, 0),
			wantAliAccounts:  nil,
			wantErr:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserMappings, gotRoleMappings, gotAliAccounts, err := ParseMap(tt.args.filename)
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
			if !reflect.DeepEqual(gotAliAccounts, tt.wantAliAccounts) {
				t.Errorf("ParseMap() gotAliAccounts = %v, want %v", gotAliAccounts, tt.wantAliAccounts)
			}
		})
	}
}

func TestParseMap_MarshalFailed(t *testing.T) {
	data := []byte("abc")
	err := os.WriteFile("dynamicfile_test.yaml", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file dynamicfile_test.yaml")
	}
	defer os.Remove("dynamicfile_test.yaml")

	type args struct {
		filename string
	}
	tests := []struct {
		name             string
		args             args
		wantUserMappings []config.UserMapping
		wantRoleMappings []config.RoleMapping
		wantAliAccounts  []string
		wantErr          bool
	}{
		{
			name: "testMarshalFailed",
			args: args{
				filename: "dynamicfile_test.yaml",
			},
			wantUserMappings: make([]config.UserMapping, 0),
			wantRoleMappings: make([]config.RoleMapping, 0),
			wantAliAccounts:  nil,
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserMappings, gotRoleMappings, gotAliAccounts, err := ParseMap(tt.args.filename)
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
			if !reflect.DeepEqual(gotAliAccounts, tt.wantAliAccounts) {
				t.Errorf("ParseMap() gotAliAccounts = %v, want %v", gotAliAccounts, tt.wantAliAccounts)
			}
		})
	}
}

func TestParseMap_EmptyUser(t *testing.T) {
	data := []byte(`
{
	"mapRoles": [
    {
      "rolearn": "acs:ram::1234567890:role/aa",
      "username": "aa",
      "groups": [
        "system:masters"
      ]
    },
    {
      "rolearn": "acs:ram::1234567890:role/bb",
      "username": "bb",
      "groups": [
        "system:users"
      ]
    }
  ],
  "mapUsers": [
    {
      "userarn": "",
      "username": "cc",
      "groups": [
        "system:masters"
      ]
    }
  ],
  "mapAccounts": [
    "01234",
    "56789"
  ]
}
`)
	err := os.WriteFile("dynamicfile_test.yaml", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file dynamicfile_test.yaml")
	}
	defer os.Remove("dynamicfile_test.yaml")

	type args struct {
		filename string
	}
	tests := []struct {
		name             string
		args             args
		wantUserMappings []config.UserMapping
		wantRoleMappings []config.RoleMapping
		wantAliAccounts  []string
		wantErr          bool
	}{
		{
			name: "testEmptyUser",
			args: args{
				filename: "dynamicfile_test.yaml",
			},
			wantUserMappings: make([]config.UserMapping, 0),
			wantRoleMappings: []config.RoleMapping{
				{
					RoleARN:  "acs:ram::1234567890:role/aa",
					Username: "aa",
					Groups: []string{
						"system:masters",
					},
				},
				{
					RoleARN:  "acs:ram::1234567890:role/bb",
					Username: "bb",
					Groups: []string{
						"system:users",
					},
				},
			},
			wantAliAccounts: []string{"01234", "56789"},
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserMappings, gotRoleMappings, gotAliAccounts, err := ParseMap(tt.args.filename)
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
			if !reflect.DeepEqual(gotAliAccounts, tt.wantAliAccounts) {
				t.Errorf("ParseMap() gotAliAccounts = %v, want %v", gotAliAccounts, tt.wantAliAccounts)
			}
		})
	}
}

func TestParseMap_EmptyRole(t *testing.T) {
	data := []byte(`
{
	"mapRoles": [
    {
      "rolearn": "",
      "username": "aa",
      "groups": [
        "system:masters"
      ]
    },
    {
      "rolearn": "acs:ram::1234567890:role/bb",
      "username": "bb",
      "groups": [
        "system:users"
      ]
    }
  ],
  "mapUsers": [
    {
      "userarn": "acs:ram::1234567890:user/cc",
      "username": "cc",
      "groups": [
        "system:masters"
      ]
    }
  ],
  "mapAccounts": [
    "01234",
    "56789"
  ]
}
`)
	err := os.WriteFile("dynamicfile_test.yaml", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file dynamicfile_test.yaml")
	}
	defer os.Remove("dynamicfile_test.yaml")

	type args struct {
		filename string
	}
	tests := []struct {
		name             string
		args             args
		wantUserMappings []config.UserMapping
		wantRoleMappings []config.RoleMapping
		wantAliAccounts  []string
		wantErr          bool
	}{
		{
			name: "testEmptyRole",
			args: args{
				filename: "dynamicfile_test.yaml",
			},
			wantUserMappings: []config.UserMapping{
				{
					UserARN:  "acs:ram::1234567890:user/cc",
					Username: "cc",
					Groups: []string{
						"system:masters",
					},
				},
			},
			wantRoleMappings: []config.RoleMapping{
				{
					RoleARN: "acs:ram::1234567890:role/bb",
					Username: "bb",
					Groups: []string{
						"system:users",
					},
				},
			},
			wantAliAccounts:  []string{"01234", "56789"},
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserMappings, gotRoleMappings, gotAliAccounts, err := ParseMap(tt.args.filename)
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
			if !reflect.DeepEqual(gotAliAccounts, tt.wantAliAccounts) {
				t.Errorf("ParseMap() gotAliAccounts = %v, want %v", gotAliAccounts, tt.wantAliAccounts)
			}
		})
	}
}

func TestParseMap_Success(t *testing.T) {
	data := []byte(`
{
	"mapRoles": [{
			"rolearn": "acs:ram::1234567890:role/aa",
			"username": "aa",
			"groups": [
				"system:masters"
			]
		},
		{
			"rolearn": "acs:ram::1234567890:role/bb",
			"username": "bb",
			"groups": [
				"system:users"
			]
		}
	],
	"mapUsers": [{
		"userarn": "acs:ram::1234567890:user/cc",
		"username": "cc",
		"groups": [
			"system:masters"
		]
	}],
	"mapAccounts": [
		"01234",
		"56789"
	]
}
`)
	err := os.WriteFile("dynamicfile_test.yaml", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file dynamicfile_test.yaml")
	}
	defer os.Remove("dynamicfile_test.yaml")

	type args struct {
		filename string
	}
	tests := []struct {
		name             string
		args             args
		wantUserMappings []config.UserMapping
		wantRoleMappings []config.RoleMapping
		wantAliAccounts  []string
		wantErr          bool
	}{
		{
			name: "testSuccess",
			args: args{
				filename: "dynamicfile_test.yaml",
			},
			wantUserMappings: []config.UserMapping{
				{
					UserARN:  "acs:ram::1234567890:user/cc",
					Username: "cc",
					Groups: []string{
						"system:masters",
					},
				},
				
			},
			wantRoleMappings: []config.RoleMapping{
				{
					RoleARN:  "acs:ram::1234567890:role/aa",
					Username: "aa",
					Groups: []string{
						"system:masters",
					},
				},
				{
					RoleARN:  "acs:ram::1234567890:role/bb",
					Username: "bb",
					Groups: []string{
						"system:users",
					},
				},
			},
			wantAliAccounts: []string{"01234", "56789"},
			wantErr:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserMappings, gotRoleMappings, gotAliAccounts, err := ParseMap(tt.args.filename)
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
			if !reflect.DeepEqual(gotAliAccounts, tt.wantAliAccounts) {
				t.Errorf("ParseMap() gotAliAccounts = %v, want %v", gotAliAccounts, tt.wantAliAccounts)
			}
		})
	}
}

func TestDynamicFileMapStore_UserMapping(t *testing.T) {
	type args struct {
		arn string
	}
	tests := []struct {
		name    string
		ms      *DynamicFileMapStore
		args    args
		want    config.UserMapping
		wantErr bool
	}{
		{
			name: "testFailed",
			ms: &DynamicFileMapStore{
				users: map[string]config.UserMapping{},
			},
			args: args{
				arn: "test",
			},
			want:    config.UserMapping{},
			wantErr: true,
		},
		{
			name: "testSuccess",
			ms: &DynamicFileMapStore{
				users: map[string]config.UserMapping{
					"test": {
						UserARN:  "aa",
						Username: "aa",
					},
				},
			},
			args: args{
				arn: "test",
			},
			want: config.UserMapping{
				UserARN:  "aa",
				Username: "aa",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ms.UserMapping(tt.args.arn)
			if (err != nil) != tt.wantErr {
				t.Errorf("DynamicFileMapStore.UserMapping() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DynamicFileMapStore.UserMapping() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDynamicFileMapStore_RoleMapping(t *testing.T) {
	type args struct {
		arn string
	}
	tests := []struct {
		name    string
		ms      *DynamicFileMapStore
		args    args
		want    config.RoleMapping
		wantErr bool
	}{
		{
			name: "testFailed",
			ms: &DynamicFileMapStore{
				roles: map[string]config.RoleMapping{},
			},
			args: args{
				arn: "test",
			},
			want:    config.RoleMapping{},
			wantErr: true,
		},
		{
			name: "testSuccess",
			ms: &DynamicFileMapStore{
				roles: map[string]config.RoleMapping{
					"test": {
						RoleARN:  "aa",
						Username: "aa",
					},
				},
			},
			args: args{
				arn: "test",
			},
			want: config.RoleMapping{
				RoleARN:  "aa",
				Username: "aa",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ms.RoleMapping(tt.args.arn)
			if (err != nil) != tt.wantErr {
				t.Errorf("DynamicFileMapStore.RoleMapping() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DynamicFileMapStore.RoleMapping() = %v, want %v", got, tt.want)
			}
		})
	}
}
