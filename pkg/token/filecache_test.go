package token

import (
	"context"
	"github.com/aliyun/credentials-go/credentials"
	"os"
	"time"
)

type stubProvider struct {
	creds   credentials.Credential
	expired bool
	err     error
}

func (s *stubProvider) Retrieve() (credentials.Credential, error) {
	s.expired = false
	return s.creds, s.err
}

func (s *stubProvider) IsExpired() bool {
	return s.expired
}

type stubProviderExpirer struct {
	stubProvider
	expiration time.Time
}

func (s *stubProviderExpirer) ExpiresAt() time.Time {
	return s.expiration
}

type testFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fs *testFileInfo) Name() string       { return fs.name }
func (fs *testFileInfo) Size() int64        { return fs.size }
func (fs *testFileInfo) Mode() os.FileMode  { return fs.mode }
func (fs *testFileInfo) ModTime() time.Time { return fs.modTime }
func (fs *testFileInfo) IsDir() bool        { return fs.Mode().IsDir() }
func (fs *testFileInfo) Sys() interface{}   { return nil }

type testFS struct {
	filename string
	fileinfo testFileInfo
	data     []byte
	err      error
	perm     os.FileMode
}

func (t *testFS) Stat(filename string) (os.FileInfo, error) {
	t.filename = filename
	if t.err == nil {
		return &t.fileinfo, nil
	} else {
		return nil, t.err
	}
}

func (t *testFS) ReadFile(filename string) ([]byte, error) {
	t.filename = filename
	return t.data, t.err
}

func (t *testFS) WriteFile(filename string, data []byte, perm os.FileMode) error {
	t.filename = filename
	t.data = data
	t.perm = perm
	return t.err
}

func (t *testFS) MkdirAll(path string, perm os.FileMode) error {
	t.filename = path
	t.perm = perm
	return t.err
}

func (t *testFS) reset() {
	t.filename = ""
	t.fileinfo = testFileInfo{}
	t.data = []byte{}
	t.err = nil
	t.perm = 0600
}

type testEnv struct {
	values map[string]string
}

func (e *testEnv) Getenv(key string) string {
	return e.values[key]
}

func (e *testEnv) LookupEnv(key string) (string, bool) {
	value, ok := e.values[key]
	return value, ok
}

func (e *testEnv) reset() {
	e.values = map[string]string{}
}

type testFilelock struct {
	ctx        context.Context
	retryDelay time.Duration
	success    bool
	err        error
}

func (l *testFilelock) Unlock() error {
	return nil
}

func (l *testFilelock) TryLockContext(ctx context.Context, retryDelay time.Duration) (bool, error) {
	l.ctx = ctx
	l.retryDelay = retryDelay
	return l.success, l.err
}

func (l *testFilelock) TryRLockContext(ctx context.Context, retryDelay time.Duration) (bool, error) {
	l.ctx = ctx
	l.retryDelay = retryDelay
	return l.success, l.err
}

func (l *testFilelock) reset() {
	l.ctx = context.TODO()
	l.retryDelay = 0
	l.success = true
	l.err = nil
}

func getMocks() (tf *testFS, te *testEnv, testFlock *testFilelock) {
	tf = &testFS{}
	tf.reset()
	f = tf
	te = &testEnv{}
	te.reset()
	e = te
	testFlock = &testFilelock{}
	testFlock.reset()
	newFlock = func(filename string) filelock {
		return testFlock
	}
	return
}
