package proxy

import (
	"sync"
	"time"
)

type ttlMap struct {
	mu sync.RWMutex
	m  map[string]ttlEntry
}

const maxTTLMapSize = 100_000

type ttlEntry struct {
	value any
	exp   time.Time
}

func newTTLMap() *ttlMap {
	return &ttlMap{m: map[string]ttlEntry{}}
}

func (m *ttlMap) Set(key string, value any, ttl time.Duration) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.m[key]; !exists && len(m.m) >= maxTTLMapSize {
		m.cleanupLocked(now)
	}
	if _, exists := m.m[key]; !exists && len(m.m) >= maxTTLMapSize {
		return
	}
	m.m[key] = ttlEntry{value: value, exp: now.Add(ttl)}
}

func (m *ttlMap) Get(key string) (any, bool) {
	now := time.Now()
	m.mu.RLock()
	entry, ok := m.m[key]
	if !ok {
		m.mu.RUnlock()
		return nil, false
	}
	if !now.After(entry.exp) {
		m.mu.RUnlock()
		return entry.value, true
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.m[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(current.exp) {
		delete(m.m, key)
		return nil, false
	}
	return current.value, true
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
	m.cleanupLocked(now)
}

func (m *ttlMap) cleanupLocked(now time.Time) {
	for key, entry := range m.m {
		if now.After(entry.exp) {
			delete(m.m, key)
		}
	}
}
