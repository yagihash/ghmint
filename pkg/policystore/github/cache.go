package github

import (
	"sync"
	"time"
)

const policyTTL = 60 * time.Second

type policyCache struct {
	mu      sync.Mutex
	entries map[string]policyCacheEntry
}

type policyCacheEntry struct {
	content []byte
	exp     time.Time
}

func newPolicyCache() *policyCache {
	return &policyCache{entries: make(map[string]policyCacheEntry)}
}

func (c *policyCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.content, true
}

func (c *policyCache) set(key string, content []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = policyCacheEntry{content: content, exp: time.Now().Add(policyTTL)}
}
