package token

import (
	"encoding/base64"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

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

func Test_tokenVerifier_parseV2Token(t *testing.T) {
	type fields struct {
		client      *http.Client
		clusterID   string
		stsEndpoint string
	}
	type args struct {
		rawToken string
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       string
		wantURL    string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "test 1",
			fields: fields{
				client:      nil,
				clusterID:   "c2faf4f7584e349cda6dda2a*********",
				stsEndpoint: "sts.example.com",
			},
			args: args{
				rawToken: "ewogICJjbHVzdGVySWQiOiAiYzJmYWY0Zjc1ODRlMzQ5Y2RhNmRkYTJhKioqKioqKioqIiwKICAibWV0aG9kIjogIlBPU1QiLAogICJwYXRoIjogIi8iLAogICJxdWVyeSI6IHsKICAgICJBQ0tDbHVzdGVySWQiOiAiYzJmYWY0Zjc1ODRlMzQ5Y2RhNmRkYTJhKioqKioqKioqIgogIH0sCiAgImhlYWRlcnMiOiB7CiAgICAiQXV0aG9yaXphdGlvbiI6ICJBQ1MzLUhNQUMtU0hBMjU2IENyZWRlbnRpYWw9KioqKioqKioqKioqU0pHVzJCKioqKioqLFNpZ25lZEhlYWRlcnM9eC1hY3MtYWN0aW9uO3gtYWNzLWNvbnRlbnQtc2hhMjU2O3gtYWNzLWRhdGU7eC1hY3MtdmVyc2lvbixTaWduYXR1cmU9ODAzODU0ODMwOTkyNzRlZWYwMDQ4YTQ5MWJjMjIwOTIxYzVlMTk1YTgzYjdmZGRlM2Y3MGM5MGMyOTY2NWYwZiIsCiAgICAidXNlci1hZ2VudCI6ICJhY2stcmFtLXRvb2wvdjAuMC4wIChkYXJ3aW4vYXJtNjQpIiwKICAgICJ4LWFjcy1hY3Rpb24iOiAiR2V0Q2FsbGVySWRlbnRpdHkiLAogICAgIngtYWNzLWNvbnRlbnQtc2hhMjU2IjogImUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUiLAogICAgIngtYWNzLWRhdGUiOiAiMjAyNC0wNy0zMVQxMTozNToyNFoiLAogICAgIngtYWNzLXZlcnNpb24iOiAiMjAxNS0wNC0wMSIKICB9Cn0K",
			},
			want:    "************SJGW2B******",
			wantURL: "https://sts.example.com/?ACKClusterId=c2faf4f7584e349cda6dda2a%2A%2A%2A%2A%2A%2A%2A%2A%2A",
			wantErr: false,
		},
		{
			name: "test 2",
			fields: fields{
				client:      nil,
				clusterID:   "c2faf4f7584e349cda6dda2a*********",
				stsEndpoint: "sts.example.com",
			},
			args: args{
				rawToken: "ewogICJxdWVyeSI6IHsKICAgICJBQ0tDbHVzdGVySWQiOiAiYzJmYWY0Zjc1ODRlMzQ5Y2RhNmRkYTJhKioqKioqKioqIgogIH0sCiAgImhlYWRlcnMiOiB7CiAgICAiQXV0aG9yaXphdGlvbiI6ICJBQ1MzLUhNQUMtU0hBMjU2IENyZWRlbnRpYWw9KioqKioqKioqKioqU0pHVzJCKioqKioqLFNpZ25lZEhlYWRlcnM9eC1hY3MtYWN0aW9uO3gtYWNzLWNvbnRlbnQtc2hhMjU2O3gtYWNzLWRhdGU7eC1hY3MtdmVyc2lvbixTaWduYXR1cmU9ODAzODU0ODMwOTkyNzRlZWYwMDQ4YTQ5MWJjMjIwOTIxYzVlMTk1YTgzYjdmZGRlM2Y3MGM5MGMyOTY2NWYwZiIsCiAgICAidXNlci1hZ2VudCI6ICJhY2stcmFtLXRvb2wvdjAuMC4wIChkYXJ3aW4vYXJtNjQpIiwKICAgICJ4LWFjcy1hY3Rpb24iOiAiR2V0Q2FsbGVySWRlbnRpdHkiLAogICAgIngtYWNzLWNvbnRlbnQtc2hhMjU2IjogImUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUiLAogICAgIngtYWNzLWRhdGUiOiAiMjAyNC0wNy0zMVQxMTozNToyNFoiLAogICAgIngtYWNzLXZlcnNpb24iOiAiMjAxNS0wNC0wMSIKICB9Cn0K",
			},
			want:    "************SJGW2B******",
			wantURL: "https://sts.example.com/?ACKClusterId=c2faf4f7584e349cda6dda2a%2A%2A%2A%2A%2A%2A%2A%2A%2A",
			wantErr: false,
		},
		{
			name: "test 2.2",
			fields: fields{
				client:      nil,
				clusterID:   "c2faf4f7584e349cda6dda2a*********",
				stsEndpoint: "sts.example.com",
			},
			args: args{
				rawToken: "ewogICJxdWVyeSI6IHsKICAgICJBQ0tDbHVzdGVySWQiOiAiYzJmYWY0Zjc1ODRlMzQ5Y2RhNmRkYTJhKioqKioqKioqIiwKICAgICJmb29iYXIiOiAidGVzdCIKICB9LAogICJoZWFkZXJzIjogewogICAgIkF1dGhvcml6YXRpb24iOiAiQUNTMy1ITUFDLVNIQTI1NiBDcmVkZW50aWFsPSoqKioqKioqKioqKlNKR1cyQioqKioqKixTaWduZWRIZWFkZXJzPXgtYWNzLWFjdGlvbjt4LWFjcy1jb250ZW50LXNoYTI1Njt4LWFjcy1kYXRlO3gtYWNzLXZlcnNpb24sU2lnbmF0dXJlPTgwMzg1NDgzMDk5Mjc0ZWVmMDA0OGE0OTFiYzIyMDkyMWM1ZTE5NWE4M2I3ZmRkZTNmNzBjOTBjMjk2NjVmMGYiLAogICAgInVzZXItYWdlbnQiOiAiYWNrLXJhbS10b29sL3YwLjAuMCAoZGFyd2luL2FybTY0KSIsCiAgICAieC1hY3MtYWN0aW9uIjogIkdldENhbGxlcklkZW50aXR5IiwKICAgICJ4LWFjcy1jb250ZW50LXNoYTI1NiI6ICJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwKICAgICJ4LWFjcy1kYXRlIjogIjIwMjQtMDctMzFUMTE6MzU6MjRaIiwKICAgICJ4LWFjcy12ZXJzaW9uIjogIjIwMTUtMDQtMDEiCiAgfQp9Cg==",
			},
			want:    "************SJGW2B******",
			wantURL: "https://sts.example.com/?ACKClusterId=c2faf4f7584e349cda6dda2a%2A%2A%2A%2A%2A%2A%2A%2A%2A",
			wantErr: false,
		},
		{
			name: "test 3",
			fields: fields{
				client:      nil,
				clusterID:   "c2faf4f7584e349cda6dda2a*********",
				stsEndpoint: "sts.example.com",
			},
			args: args{
				rawToken: "ewogICJxdWVyeSI6IHsKICAgICJBQ0tDbHVzdGVySWQiOiAiY0FBQUFBQUFBODRlMzQ5Y2RhNmRkYTJhKioqKioqKioqIgogIH0sCiAgImhlYWRlcnMiOiB7CiAgICAiQXV0aG9yaXphdGlvbiI6ICJBQ1MzLUhNQUMtU0hBMjU2IENyZWRlbnRpYWw9KioqKioqKioqKioqU0pHVzJCKioqKioqLFNpZ25lZEhlYWRlcnM9eC1hY3MtYWN0aW9uO3gtYWNzLWNvbnRlbnQtc2hhMjU2O3gtYWNzLWRhdGU7eC1hY3MtdmVyc2lvbixTaWduYXR1cmU9ODAzODU0ODMwOTkyNzRlZWYwMDQ4YTQ5MWJjMjIwOTIxYzVlMTk1YTgzYjdmZGRlM2Y3MGM5MGMyOTY2NWYwZiIsCiAgICAidXNlci1hZ2VudCI6ICJhY2stcmFtLXRvb2wvdjAuMC4wIChkYXJ3aW4vYXJtNjQpIiwKICAgICJ4LWFjcy1hY3Rpb24iOiAiR2V0Q2FsbGVySWRlbnRpdHkiLAogICAgIngtYWNzLWNvbnRlbnQtc2hhMjU2IjogImUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUiLAogICAgIngtYWNzLWRhdGUiOiAiMjAyNC0wNy0zMVQxMTozNToyNFoiLAogICAgIngtYWNzLXZlcnNpb24iOiAiMjAxNS0wNC0wMSIKICB9Cn0K",
			},
			want:       "",
			wantURL:    "",
			wantErr:    true,
			wantErrMsg: "unexpected clusterid",
		},
		{
			name: "test 3.2",
			fields: fields{
				client:      nil,
				clusterID:   "c2faf4f7584e349cda6dda2a*********",
				stsEndpoint: "sts.example.com",
			},
			args: args{
				rawToken: "ewogICJoZWFkZXJzIjogewogICAgIkF1dGhvcml6YXRpb24iOiAiQUNTMy1ITUFDLVNIQTI1NiBDcmVkZW50aWFsPSoqKioqKioqKioqKlNKR1cyQioqKioqKixTaWduZWRIZWFkZXJzPXgtYWNzLWFjdGlvbjt4LWFjcy1jb250ZW50LXNoYTI1Njt4LWFjcy1kYXRlO3gtYWNzLXZlcnNpb24sU2lnbmF0dXJlPTgwMzg1NDgzMDk5Mjc0ZWVmMDA0OGE0OTFiYzIyMDkyMWM1ZTE5NWE4M2I3ZmRkZTNmNzBjOTBjMjk2NjVmMGYiLAogICAgInVzZXItYWdlbnQiOiAiYWNrLXJhbS10b29sL3YwLjAuMCAoZGFyd2luL2FybTY0KSIsCiAgICAieC1hY3MtYWN0aW9uIjogIkdldENhbGxlcklkZW50aXR5IiwKICAgICJ4LWFjcy1jb250ZW50LXNoYTI1NiI6ICJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1IiwKICAgICJ4LWFjcy1kYXRlIjogIjIwMjQtMDctMzFUMTE6MzU6MjRaIiwKICAgICJ4LWFjcy12ZXJzaW9uIjogIjIwMTUtMDQtMDEiCiAgfQp9Cg==",
			},
			want:       "",
			wantURL:    "",
			wantErr:    true,
			wantErrMsg: "unexpected clusterid",
		},
		{
			name: "test 4",
			fields: fields{
				client:      nil,
				clusterID:   "c2faf4f7584e349cda6dda2a*********",
				stsEndpoint: "sts.example.com",
			},
			args: args{
				rawToken: "ewogICJxdWVyeSI6IHsKICAgICJBQ0tDbHVzdGVySWQiOiAiYzJmYWY0Zjc1ODRlMzQ5Y2RhNmRkYTJhKioqKioqKioqIgogIH0sCiAgImhlYWRlcnMiOiB7CiAgICAiQXV0aG9yaXphdGlvbiI6ICJBQ1MzLUhNQUMtU0hBMjU2IENyZWRlbnRpYWw9KioqKioqKioqKioqU0pHVzJCKioqKioqLFNpZ25lZEhlYWRlcnM9eC1hY3MtYWN0aW9uO3gtYWNzLWNvbnRlbnQtc2hhMjU2O3gtYWNzLWRhdGU7eC1hY3MtdmVyc2lvbixTaWduYXR1cmU9ODAzODU0ODMwOTkyNzRlZWYwMDQ4YTQ5MWJjMjIwOTIxYzVlMTk1YTgzYjdmZGRlM2Y3MGM5MGMyOTY2NWYwZiIsCiAgICAidXNlci1hZ2VudCI6ICJhY2stcmFtLXRvb2wvdjAuMC4wIChkYXJ3aW4vYXJtNjQpIiwKICAgICJ4LWFjcy1hY3Rpb24iOiAiR2V0Q2FsbGVySWRlbnRpdHlYWCIsCiAgICAieC1hY3MtY29udGVudC1zaGEyNTYiOiAiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NSIsCiAgICAieC1hY3MtZGF0ZSI6ICIyMDI0LTA3LTMxVDExOjM1OjI0WiIsCiAgICAieC1hY3MtdmVyc2lvbiI6ICIyMDE1LTA0LTAxIgogIH0KfQo=",
			},
			want:       "",
			wantURL:    "",
			wantErr:    true,
			wantErrMsg: "unexpected action",
		},
		{
			name: "test 5",
			fields: fields{
				client:      nil,
				clusterID:   "c2faf4f7584e349cda6dda2a*********",
				stsEndpoint: "sts.example.com",
			},
			args: args{
				rawToken: "e30K",
			},
			want:       "",
			wantURL:    "",
			wantErr:    true,
			wantErrMsg: "unexpected clusterid",
		},
		{
			name: "test 6",
			fields: fields{
				client:      nil,
				clusterID:   "c2faf4f7584e349cda6dda2a*********",
				stsEndpoint: "sts.example.com",
			},
			args: args{
				rawToken: "foobar",
			},
			want:       "",
			wantURL:    "",
			wantErr:    true,
			wantErrMsg: "invalid character",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tokenVerifier{
				client:      tt.fields.client,
				clusterID:   tt.fields.clusterID,
				stsEndpoint: tt.fields.stsEndpoint,
			}
			token, _ := base64.StdEncoding.DecodeString(tt.args.rawToken)
			got, got1, err := v.parseV2Token(string(token))
			t.Log(err)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseV2Token() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseV2Token() got = %v, want %v", got, tt.want)
			}
			if err == nil {
				if !reflect.DeepEqual(got1.URL.String(), tt.wantURL) {
					t.Errorf("parseV2Token() got1 = %v, want %v", got1.URL.String(), tt.wantURL)
				}
			} else {
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("want error include %q, but got %q", tt.wantErrMsg, err.Error())
				}
			}
		})
	}
}
