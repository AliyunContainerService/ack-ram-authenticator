package dynamicfile

import (
	"reflect"
	"testing"

	"github.com/AliyunContainerService/ack-ram-authenticator/pkg/config"
)

func TestDynamicFileMapper_Map(t *testing.T) {
	type args struct {
		canonicalARN string
	}
	tests := []struct {
		name    string
		m       *DynamicFileMapper
		args    args
		want    *config.IdentityMapping
		wantErr string
	}{
		{
			name: "testNotMapped",
			m:    &DynamicFileMapper{
				&DynamicFileMapStore{},
			},
			args: args{
				canonicalARN: "test",
			},
			want:    nil,
			wantErr: "ARN is not mapped",
		},
		{
			name: "testRole",
			m: &DynamicFileMapper{
				&DynamicFileMapStore{
					roles: map[string]config.RoleMapping{
						"aa": {
							Username: "aa",
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
				Groups:      nil,
			},
			wantErr: "",
		},
		{
			name: "testUser",
			m: &DynamicFileMapper{
				&DynamicFileMapStore{
					users: map[string]config.UserMapping{
						"bb": {
							Username: "bb",
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
				Groups:      nil,
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.Map(tt.args.canonicalARN)
			if (err != nil) && err.Error() != tt.wantErr {
				t.Errorf("DynamicFileMapper.Map() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DynamicFileMapper.Map() = %v, want %v", got, tt.want)
			}
		})
	}
}
