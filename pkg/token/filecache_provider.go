package token

import (
	"context"
	"errors"
	"fmt"
	openapi "github.com/alibabacloud-go/darabonba-openapi/client"
	sts "github.com/alibabacloud-go/sts-20150401/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/gofrs/flock"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v2"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// env variable name for custom credential cache file location
const (
	ENVCredentialFile  = "ALIBABA_CLOUD_CREDENTIALS_FILE"
	PATHCredentialFile = "~/.alibabacloud/credentials"
	cacheFileNameEnv   = "ACK_RAM_AUTHENTICATOR_CACHE_FILE"
	RamRoleARNAuthType = "ram_role_arn"
)

// A mockable filesystem interface
var f filesystem = osFS{}

type filesystem interface {
	Stat(filename string) (os.FileInfo, error)
	ReadFile(filename string) ([]byte, error)
	WriteFile(filename string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
}

// default os based implementation
type osFS struct{}

func (osFS) Stat(filename string) (os.FileInfo, error) {
	return os.Stat(filename)
}

func (osFS) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func (osFS) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return ioutil.WriteFile(filename, data, perm)
}

func (osFS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// A mockable environment interface
var e environment = osEnv{}

type environment interface {
	Getenv(key string) string
	LookupEnv(key string) (string, bool)
}

// default os based implementation
type osEnv struct{}

func (osEnv) Getenv(key string) string {
	return os.Getenv(key)
}

func (osEnv) LookupEnv(key string) (string, bool) {
	return os.LookupEnv(key)
}

type Credential struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	Expiration      time.Time
}

// A mockable flock interface
type filelock interface {
	Unlock() error
	TryLockContext(ctx context.Context, retryDelay time.Duration) (bool, error)
	TryRLockContext(ctx context.Context, retryDelay time.Duration) (bool, error)
}

var newFlock = func(filename string) filelock {
	return flock.New(filename)
}

// cacheFile is a map of clusterID/roleARNs to cached credentials
type cacheFile struct {
	// a map of clusterIDs/profiles/roleARNs to cachedCredentials
	ClusterMap map[string]map[string]map[string]cachedCredential `yaml:"clusters"`
}

// a utility type for dealing with compound cache keys
type cacheKey struct {
	clusterID string
	profile   string
	roleARN   string
}

// a utility type for ram role arn crendential configuration
type profileConfig struct {
	accessKey       string
	accessSecret    string
	roleARN         string
	roleSessionName string
}

// FileCacheProvider is a Provider implementation that wraps an underlying Provider
// (contained in Credentials) and provides caching support for credentials for the
// specified clusterID, profile, and roleARN (contained in cacheKey)
type FileCacheProvider struct {
	pc               profileConfig
	stsEndpoint      string
	cacheKey         cacheKey         // cache key parameters used to create Provider
	cachedCredential cachedCredential // the cached credential, if it exists
}

func (c *cacheFile) Put(key cacheKey, credential cachedCredential) {
	if _, ok := c.ClusterMap[key.clusterID]; !ok {
		// first use of this cluster id
		c.ClusterMap[key.clusterID] = map[string]map[string]cachedCredential{}
	}
	if _, ok := c.ClusterMap[key.clusterID][key.profile]; !ok {
		// first use of this profile
		c.ClusterMap[key.clusterID][key.profile] = map[string]cachedCredential{}
	}
	c.ClusterMap[key.clusterID][key.profile][key.roleARN] = credential
}

func (c *cacheFile) Get(key cacheKey) (credential cachedCredential) {
	if _, ok := c.ClusterMap[key.clusterID]; ok {
		if _, ok := c.ClusterMap[key.clusterID][key.profile]; ok {
			// we at least have this cluster and profile combo in the map, if no matching roleARN, map will
			// return the zero-value for cachedCredential, which expired a long time ago.
			credential = c.ClusterMap[key.clusterID][key.profile][key.roleARN]
		}
	}
	return
}

// cachedCredential is a single cached credential entry, along with expiration time
type cachedCredential struct {
	Credential *Credential
	Expiration time.Time
	// If set will be used by IsExpired to determine the current time.
	// Defaults to time.Now if CurrentTime is not set.  Available for testing
	// to be able to mock out the current time.
	currentTime func() time.Time
}

// IsExpired determines if the cached credential has expired
func (c *cachedCredential) IsExpired() bool {
	curTime := c.currentTime
	if curTime == nil {
		curTime = time.Now
	}
	return c.Expiration.Before(curTime())
}

// readCacheWhileLocked reads the contents of the credential cache and returns the
// parsed yaml as a cacheFile object.  This method must be called while a shared
// lock is held on the filename.
func readCacheWhileLocked(filename string) (cache cacheFile, err error) {
	cache = cacheFile{
		map[string]map[string]map[string]cachedCredential{},
	}
	data, err := f.ReadFile(filename)
	if err != nil {
		err = fmt.Errorf("unable to open file %s: %v", filename, err)
		return
	}

	err = yaml.Unmarshal(data, &cache)
	if err != nil {
		err = fmt.Errorf("unable to parse file %s: %v", filename, err)
	}
	return
}

// writeCacheWhileLocked writes the contents of the credential cache using the
// yaml marshaled form of the passed cacheFile object.  This method must be
// called while an exclusive lock is held on the filename.
func writeCacheWhileLocked(filename string, cache cacheFile) error {
	data, err := yaml.Marshal(cache)
	if err == nil {
		// write privately owned by the user
		err = f.WriteFile(filename, data, 0600)
	}
	return err
}

func (p *FileCacheProvider) GetCredential(ctx context.Context) (*Credential, error) {
	return p.retrieve()
}

// NewFileCacheProvider creates a new Provider implementation that wraps a provided Credentials,
// and works with an on disk cache to speed up credential usage when the cached copy is not expired.
// If there are any problems accessing or initializing the cache, an error will be returned, and
// callers should just use the existing credentials provider.
func NewFileCacheProvider(clusterID, profile, roleARN, stsEndpoint string, pc *profileConfig) (FileCacheProvider, error) {
	if pc == nil {
		return FileCacheProvider{}, errors.New("no sts client object provided")
	}
	filename := CacheFilename()
	cacheKey := cacheKey{clusterID, profile, roleARN}
	cachedCredential := cachedCredential{}
	// ensure path to cache file exists
	_ = f.MkdirAll(filepath.Dir(filename), 0700)
	if info, err := f.Stat(filename); err == nil {
		if info.Mode()&0077 != 0 {
			// cache file has secret credentials and should only be accessible to the user, refuse to use it.
			return FileCacheProvider{}, fmt.Errorf("cache file %s is not private", filename)
		}

		// do file locking on cache to prevent inconsistent reads
		lock := newFlock(filename)
		defer lock.Unlock()
		// wait up to a second for the file to lock
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()
		ok, err := lock.TryRLockContext(ctx, 250*time.Millisecond) // try to lock every 1/4 second
		if !ok {
			// unable to lock the cache, something is wrong, refuse to use it.
			return FileCacheProvider{}, fmt.Errorf("unable to read lock file %s: %v", filename, err)
		}

		cache, err := readCacheWhileLocked(filename)
		if err != nil {
			// can't read or parse cache, refuse to use it.
			return FileCacheProvider{}, err
		}

		cachedCredential = cache.Get(cacheKey)
	} else {
		if errors.Is(err, fs.ErrNotExist) {
			// cache file is missing.  maybe this is the very first run?  continue to use cache.
			_, _ = fmt.Fprintf(os.Stderr, "Cache file %s does not exist.\n", filename)
		} else {
			return FileCacheProvider{}, fmt.Errorf("couldn't stat cache file: %w", err)
		}
	}

	return FileCacheProvider{
		*pc,
		stsEndpoint,
		cacheKey,
		cachedCredential,
	}, nil
}

func (f *FileCacheProvider) retrieve() (*Credential, error) {
	if !f.cachedCredential.IsExpired() {
		// use the cached credential
		return f.cachedCredential.Credential, nil
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "No cached credential available.  Refreshing...\n")
		var cred *Credential
		roleArn := f.pc.roleARN
		// assume role again to renew credential
		config := new(credentials.Config).
			SetType(RamRoleARNAuthType).
			SetAccessKeyId(f.pc.accessKey).
			SetAccessKeySecret(f.pc.accessSecret).
			SetRoleArn(roleArn).
			SetRoleSessionExpiration(3600)
		tokenCred, err := credentials.NewCredential(config)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to renew credential when assume role %s: %v\n", roleArn, err)
			return cred, fmt.Errorf("failed to assume ram role %s, err %v", roleArn, err)
		}

		stsAPI, err := sts.NewClient(&openapi.Config{
			Endpoint:   tea.String(f.stsEndpoint),
			Protocol:   tea.String(defaultSTSProtocol),
			Credential: tokenCred,
		})
		expiration := time.Now().Local().Add(3600*time.Second - 1*time.Minute)
		stsReq := &sts.AssumeRoleRequest{
			RoleArn:         tea.String(f.pc.roleARN),
			RoleSessionName: tea.String(fmt.Sprintf("%s-%d", defaultRoleSessionName, time.Now().UnixNano())),
		}
		assumeRes, err := stsAPI.AssumeRole(stsReq)
		if err != nil {
			return cred, fmt.Errorf("failed to assume ram role %s, err %v", roleArn, err)
		}
		cred.AccessKeyId = tea.StringValue(assumeRes.Body.Credentials.AccessKeyId)
		cred.AccessKeySecret = tea.StringValue(assumeRes.Body.Credentials.AccessKeySecret)
		cred.SecurityToken = tea.StringValue(assumeRes.Body.Credentials.SecurityToken)

		// underlying provider supports Expirer interface, so we can cache
		filename := CacheFilename()
		// do file locking on cache to prevent inconsistent writes
		lock := newFlock(filename)
		defer lock.Unlock()
		// wait up to a second for the file to lock
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()
		ok, err := lock.TryLockContext(ctx, 250*time.Millisecond) // try to lock every 1/4 second
		if !ok {
			// can't get write lock to create/update cache, but still return the credential
			_, _ = fmt.Fprintf(os.Stderr, "Unable to write lock file %s: %v\n", filename, err)
			return cred, nil
		}
		f.cachedCredential = cachedCredential{
			cred,
			expiration,
			nil,
		}
		// don't really care about read error.  Either read the cache, or we create a new cache.
		cache, _ := readCacheWhileLocked(filename)
		cache.Put(f.cacheKey, f.cachedCredential)
		err = writeCacheWhileLocked(filename, cache)
		if err != nil {
			// can't write cache, but still return the credential
			_, _ = fmt.Fprintf(os.Stderr, "Unable to update credential cache %s: %v\n", filename, err)
			err = nil
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Updated cached credential\n")
		}

		return cred, err
	}
}

// IsExpired() implements the Provider interface, deferring to the cached credential first,
// but fall back to the underlying Provider if it is expired.
func (f *FileCacheProvider) IsExpired() bool {
	return f.cachedCredential.IsExpired()
}

// ExpiresAt implements the Expirer interface, and gives access to the expiration time of the credential
func (f *FileCacheProvider) ExpiresAt() time.Time {
	return f.cachedCredential.Expiration
}

// CacheFilename returns the name of the credential cache file, which can either be
// set by environment variable, or use the default of ~/.kube/cache/ack-ram-authenticator/credentials.yaml
func CacheFilename() string {
	if filename, ok := e.LookupEnv(cacheFileNameEnv); ok {
		return filename
	} else {
		return filepath.Join(UserHomeDir(), ".kube", "cache", "ack-ram-authenticator", "credentials.yaml")
	}
}

// UserHomeDir returns the home directory for the user the process is
// running under.
func UserHomeDir() string {
	if runtime.GOOS == "windows" { // Windows
		return e.Getenv("USERPROFILE")
	}

	// *nix
	return e.Getenv("HOME")
}

// GetHomePath return home directory according to the system.
// if the environmental virables does not exist, will return empty
func GetHomePath() string {
	if runtime.GOOS == "windows" {
		path, ok := os.LookupEnv("USERPROFILE")
		if !ok {
			return ""
		}
		return path
	}
	path, ok := os.LookupEnv("HOME")
	if !ok {
		return ""
	}
	return path
}

func checkDefaultPath() (path string, err error) {
	path = GetHomePath()
	if path == "" {
		return "", errors.New("The default credential file path is invalid")
	}
	path = strings.Replace(PATHCredentialFile, "~", path, 1)
	_, err = os.Stat(path)
	if err != nil {
		return "", nil
	}
	return path, nil
}

func getRamRoleArnProfile(profile string) *profileConfig {
	path, ok := os.LookupEnv(ENVCredentialFile)
	if !ok {
		var err error
		path, err = checkDefaultPath()
		if err != nil || path == "" {
			_, _ = fmt.Fprintf(os.Stderr, "not found credential file in default path")
			return nil
		}
	} else if path == "" {
		_, _ = fmt.Fprintf(os.Stderr, "Environment variable '"+ENVCredentialFile+"' cannot be empty")
		return nil
	}

	ini, err := ini.Load(path)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: Can not open file"+err.Error())
		return nil
	}

	section, err := ini.GetSection(profile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: Can not load section"+err.Error())
		return nil
	}

	value, err := section.GetKey("type")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: Can not find credential type"+err.Error())
		return nil
	}

	switch value.String() {
	case "ram_role_arn":
		value1, err1 := section.GetKey("access_key_id")
		value2, err2 := section.GetKey("access_key_secret")
		value3, err3 := section.GetKey("role_arn")
		value4, err4 := section.GetKey("role_session_name")
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			_, _ = fmt.Fprintf(os.Stderr, "ERROR: Failed to get value")
			return nil
		}
		if value1.String() == "" || value2.String() == "" || value3.String() == "" || value4.String() == "" {
			_, _ = fmt.Fprintf(os.Stderr, "ERROR: Value can't be empty")
			return nil
		}
		return &profileConfig{
			accessKey:       value1.String(),
			accessSecret:    value2.String(),
			roleARN:         value3.String(),
			roleSessionName: value4.String(),
		}
	}
	_, _ = fmt.Fprintf(os.Stderr, "Info: Not found ram_role_arn type in profile configuration")
	return nil
}
