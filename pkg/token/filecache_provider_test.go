package token

import (
	"os"
	"reflect"
	"testing"
	"time"
)

// Mock filesystem implementation for testing purposes.
type mockFs struct{}

// Mock method for MkdirAll that always returns no error.
func (m mockFs) MkdirAll(string, os.FileMode) error {
	return nil
}

// Mock method for Stat that always returns no error.
func (m mockFs) Stat(string) (os.FileInfo, error) {
	return os.Stat("aabbcc")
}

func (m mockFs) ReadFile(filename string) ([]byte, error) {
	return nil, nil
}

func (m mockFs) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return nil
}

type args struct {
	clusterID   string
	profile     string
	roleARN     string
	stsEndpoint string
	pc          *profileConfig
}

func TestNewFileCacheProvider_EmptyPC(t *testing.T) {
	test := struct {
		name    string
		args    args
		want    FileCacheProvider
		wantErr string
	}{
		name: "testEmptyPC",
		args: args{
			clusterID:   "1234567890",
			profile:     "testProfile",
			roleARN:     "testRoleARN",
			stsEndpoint: "cn-shanghai",
			pc:          nil,
		},
		want:    FileCacheProvider{},
		wantErr: "no sts client object provided",
	}

	t.Run(test.name, func(t *testing.T) {
		got, err := NewFileCacheProvider(test.args.clusterID, test.args.profile, test.args.roleARN, test.args.stsEndpoint, test.args.pc)
		if (err != nil) && err.Error() != test.wantErr {
			t.Errorf("NewFileCacheProvider() error = %s, wantErr %s", err.Error(), test.wantErr)
			return
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("NewFileCacheProvider() = %v, want %v", got, test.want)
		}
	})
}

func TestNewFileCacheProvider_InvalidFilePermission(t *testing.T) {
	f = mockFs{}
	err := os.MkdirAll("aabbcc", 0600)
	if err != nil {
		t.Fatalf("Could not mkdirall aabbcc: %v", err)
	}
	defer os.Remove("aabbcc")

	test := struct {
		name    string
		args    args
		want    FileCacheProvider
		wantErr string
	}{
		name: "testInvalidFilePermission",
		args: args{
			clusterID:   "1234567890",
			profile:     "testProfile",
			roleARN:     "testRoleARN",
			stsEndpoint: "cn-shanghai",
			pc:          &profileConfig{},
		},
		want:    FileCacheProvider{},
		wantErr: "cache file C:\\Users\\lijiuxing\\.kube\\cache\\ack-ram-authenticator\\credentials.yaml is not private",
	}

	t.Run(test.name, func(t *testing.T) {
		got, err := NewFileCacheProvider(test.args.clusterID, test.args.profile, test.args.roleARN, test.args.stsEndpoint, test.args.pc)
		if (err != nil) && err.Error() != test.wantErr {
			t.Errorf("NewFileCacheProvider() error = %s, wantErr %s", err.Error(), test.wantErr)
			return
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("NewFileCacheProvider() = %v, want %v", got, test.want)
		}
	})
}

func TestNewFileCacheProvider_Success(t *testing.T) {
	test := struct {
		name    string
		args    args
		want    FileCacheProvider
		wantErr string
	}{
		name: "testSuccess",
		args: args{
			clusterID:   "1234567890",
			profile:     "testProfile",
			roleARN:     "testRoleARN",
			stsEndpoint: "cn-shanghai",
			pc:          &profileConfig{},
		},
		want: FileCacheProvider{
			pc:          profileConfig{},
			stsEndpoint: "cn-shanghai",
			cacheKey: cacheKey{
				clusterID: "1234567890",
				profile:   "testProfile",
				roleARN:   "testRoleARN",
			},
			cachedCredential: cachedCredential{
				Credential:  nil,
				Expiration:  time.Time{},
				currentTime: nil,
			},
		},
		wantErr: "",
	}

	t.Run(test.name, func(t *testing.T) {
		got, err := NewFileCacheProvider(test.args.clusterID, test.args.profile, test.args.roleARN, test.args.stsEndpoint, test.args.pc)
		if (err != nil) && err.Error() != test.wantErr {
			t.Errorf("NewFileCacheProvider() error = %s, wantErr %s", err.Error(), test.wantErr)
			return
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("NewFileCacheProvider() = %v, want %v", got, test.want)
		}
	})
}

func Test_checkDefaultPathFail(t *testing.T) {
	tests := []struct {
		name     string
		wantPath string
		wantErr  string
	}{
		{
			name:     "testFail",
			wantPath: "",
			wantErr:  "The default credential file path is invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := checkDefaultPath()
			if (err != nil) && err.Error() != tt.wantErr {
				t.Errorf("checkDefaultPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPath != tt.wantPath {
				t.Errorf("checkDefaultPath() = %v, want %v", gotPath, tt.wantPath)
			}
		})
	}
}

func Test_checkDefaultPathSuccess(t *testing.T) {
	err := os.Setenv("USERPROFILE", "USERPROFILE")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv("USERPROFILE")

	tests := []struct {
		name     string
		wantPath string
		wantErr  string
	}{
		{
			name:     "testSuccess",
			wantPath: "",
			wantErr:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := checkDefaultPath()
			if err != nil {
				t.Errorf("checkDefaultPath() error = %v, wantErr nil", err)
				return
			}
			if gotPath != tt.wantPath {
				t.Errorf("checkDefaultPath() = %v, want %v", gotPath, tt.wantPath)
			}
		})
	}
}

func Test_checkDefaultPathSuccessPath(t *testing.T) {
	err := os.Setenv("USERPROFILE", "aabbcc")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv("USERPROFILE")

	err = os.MkdirAll("aabbcc/.alibabacloud/credentials", 0)
	if err != nil {
		t.Fatal("mkdir aabbcc//.alibabacloud/credentials fail")
	}
	defer os.RemoveAll("aabbcc")

	tests := []struct {
		name     string
		wantPath string
		wantErr  string
	}{
		{
			name:     "testSuccess",
			wantPath: "aabbcc/.alibabacloud/credentials",
			wantErr:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := checkDefaultPath()
			if err != nil {
				t.Errorf("checkDefaultPath() error = %v, wantErr nil", err)
				return
			}
			if gotPath != tt.wantPath {
				t.Errorf("checkDefaultPath() = %v, want %v", gotPath, tt.wantPath)
			}
		})
	}
}

func Test_getRamRoleArnProfileNoEnv(t *testing.T) {
	type args struct {
		profile string
	}
	tests := []struct {
		name string
		args args
		want *profileConfig
	}{
		{
			name: "testNoEnv",
			args: args{
				profile: "test",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRamRoleArnProfile(tt.args.profile); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getRamRoleArnProfile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getRamRoleArnProfileLoadFail(t *testing.T) {
	err := os.Setenv("USERPROFILE", "aabbcc")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv("USERPROFILE")

	err = os.MkdirAll("aabbcc/.alibabacloud/credentials", 0)
	if err != nil {
		t.Fatal("mkdir aabbcc/.alibabacloud/credentials fail")
	}
	defer os.RemoveAll("aabbcc")

	err = os.Setenv(ENVCredentialFile, "aabbcc")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv(ENVCredentialFile)

	type args struct {
		profile string
	}
	tests := []struct {
		name string
		args args
		want *profileConfig
	}{
		{
			name: "testLoadFail",
			args: args{
				profile: "test",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRamRoleArnProfile(tt.args.profile); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getRamRoleArnProfile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getRamRoleArnProfileIniFail(t *testing.T) {
	err := os.Setenv("USERPROFILE", "aabbcc")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv("USERPROFILE")

	err = os.MkdirAll("aabbcc/.alibabacloud/credentials", 0)
	if err != nil {
		t.Fatal("mkdir aabbcc/.alibabacloud/credentials fail")
	}
	defer os.RemoveAll("aabbcc")

	err = os.Setenv(ENVCredentialFile, "112233")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv(ENVCredentialFile)

	file, err := os.Create("112233")
	if err != nil {
		t.Fatal("mkdir 112233 fail")
	}
	defer os.Remove("112233")
	defer file.Close()

	type args struct {
		profile string
	}
	tests := []struct {
		name string
		args args
		want *profileConfig
	}{
		{
			name: "testIniFail",
			args: args{
				profile: "test",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRamRoleArnProfile(tt.args.profile); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getRamRoleArnProfile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getRamRoleArnProfileGetKeyFail(t *testing.T) {
	err := os.Setenv("USERPROFILE", "aabbcc")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv("USERPROFILE")

	err = os.MkdirAll("aabbcc/.alibabacloud/credentials", 0)
	if err != nil {
		t.Fatal("mkdir aabbcc/.alibabacloud/credentials fail")
	}
	defer os.RemoveAll("aabbcc")

	file, err := os.Create("112233.ini")
	if err != nil {
		t.Fatal("mkdir 112233.ini fail")
	}
	defer os.Remove("112233.ini")
	defer file.Close()

	_, err = file.WriteString(`[server]
	type = a`)
	if err != nil {
		t.Fatal("write 112233.ini fail")
	}
	
	err = os.Setenv(ENVCredentialFile, "112233.ini")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv(ENVCredentialFile)

	type args struct {
		profile string
	}
	tests := []struct {
		name string
		args args
		want *profileConfig
	}{
		{
			name: "testGetKeyFail",
			args: args{
				profile: "server",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRamRoleArnProfile(tt.args.profile); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getRamRoleArnProfile() = %v, want %v", got, tt.want)
			}
		})
	}
}


func Test_getRamRoleArnProfileSuccess(t *testing.T) {
	err := os.Setenv("USERPROFILE", "aabbcc")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv("USERPROFILE")

	err = os.MkdirAll("aabbcc/.alibabacloud/credentials", 0)
	if err != nil {
		t.Fatal("mkdir aabbcc/.alibabacloud/credentials fail")
	}
	defer os.RemoveAll("aabbcc")

	file, err := os.Create("112233.ini")
	if err != nil {
		t.Fatal("mkdir 112233.ini fail")
	}
	defer os.Remove("112233.ini")
	defer file.Close()

	_, err = file.WriteString(`[server]
	type = ram_role_arn
	access_key_id=b
	access_key_secret=c
	role_arn=d
	role_session_name=e`)
	if err != nil {
		t.Fatal("write 112233.ini fail")
	}
	
	err = os.Setenv(ENVCredentialFile, "112233.ini")
	if err != nil {
		t.Fatal("set env fail")
	}
	defer os.Unsetenv(ENVCredentialFile)

	type args struct {
		profile string
	}
	tests := []struct {
		name string
		args args
		want *profileConfig
	}{
		{
			name: "testSuccess",
			args: args{
				profile: "server",
			},
			want: &profileConfig{
				accessKey: "b",
				accessSecret: "c",
				roleARN: "d",
				roleSessionName: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRamRoleArnProfile(tt.args.profile); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getRamRoleArnProfile() = %v, want %v", got, tt.want)
			}
		})
	}
}

