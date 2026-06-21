package capture

import (
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var captureFileLocks sync.Map

// WithFileLock serializes operations that mutate the same capture file path.
func WithFileLock(path string, fn func() error) error {
	lock := captureFileLock(path)
	lock.Lock()
	defer lock.Unlock()
	return fn()
}

func captureFileLock(path string) *sync.Mutex {
	key := captureFileLockKey(path)
	actual, _ := captureFileLocks.LoadOrStore(key, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

func captureFileLockKey(path string) string {
	key := path
	if abs, err := filepath.Abs(path); err == nil {
		key = abs
	}
	key = filepath.Clean(key)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key
}
