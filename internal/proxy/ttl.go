package proxy

import (
	"sync"
	"time"
)

type ttlMap struct {
	mu sync.Mutex
	m  map[string]ttlEntry
}

type ttlEntry struct {
	value any
	exp   time.Time
}

func newTTLMap() *ttlMap {
	return &ttlMap{m: map[string]ttlEntry{}}
}

func (m *ttlMap) Set(key string, value any, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[key] = ttlEntry{value: value, exp: time.Now().Add(ttl)}
}

func (m *ttlMap) Get(key string) (any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.m[key]
	if !ok || time.Now().After(entry.exp) {
		if ok {
			delete(m.m, key)
		}
		return nil, false
	}
	return entry.value, true
}

func (m *ttlMap) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, key)
}

func (m *ttlMap) DeletePrefix(prefix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.m {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(m.m, key)
		}
	}
}

func (m *ttlMap) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for key, entry := range m.m {
		if now.After(entry.exp) {
			delete(m.m, key)
		}
	}
}
