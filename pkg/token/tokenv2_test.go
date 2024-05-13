package token

import "testing"

func Test_getAccessKeyIdFromV2Header(t *testing.T) {
	type args struct {
		rawV string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "found",
			args: args{
				rawV: "ACS3-HMAC-SHA256 Credential=foobar.test.xxx,SignedHeaders=x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-version,Signature=a95a73618cadfff642167dae46a2439ea008a2e6bbe5872a85abbd2241710f91",
			},
			want: "foobar.test.xxx",
		},
		{
			name: "not foud",
			args: args{
				rawV: "ACS3-HMAC-SHA256 Credential=,SignedHeaders=x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-version,Signature=a95a73618cadfff642167dae46a2439ea008a2e6bbe5872a85abbd2241710f91",
			},
			want: "",
		},
		{
			name: "not foud 2",
			args: args{
				rawV: "ACS3-HMAC-SHA256 Credential=foobar",
			},
			want: "",
		},
		{
			name: "not foud 3",
			args: args{
				rawV: "foobar",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAccessKeyIdFromV2Header(tt.args.rawV); got != tt.want {
				t.Errorf("getAccessKeyIdFromV2Header() = %v, want %v", got, tt.want)
			}
		})
	}
}
