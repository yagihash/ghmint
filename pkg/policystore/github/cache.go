package github

import (
	"sync"
	"time"
)

const (
	installIDTTL      = 60 * time.Minute
	tokenSafetyMargin = 5 * time.Minute
	policyTTL         = 60 * time.Second
)

type cache struct {
	mu           sync.Mutex
	installID    map[string]idEntry
	installToken map[string]tokenEntry
	policy       map[string]policyEntry
}

type idEntry struct {
	id  int64
	exp time.Time
}

type tokenEntry struct {
	token string
	exp   time.Time
}

type policyEntry struct {
	content []byte
	exp     time.Time
}

func newCache() *cache {
	return &cache{
		installID:    make(map[string]idEntry),
		installToken: make(map[string]tokenEntry),
		policy:       make(map[string]policyEntry),
	}
}

func (c *cache) getInstallID(owner string) (int64, bool) {
	if c == nil {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.installID[owner]
	if !ok || time.Now().After(e.exp) {
		return 0, false
	}
	return e.id, true
}

func (c *cache) setInstallID(owner string, id int64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.installID[owner] = idEntry{id: id, exp: time.Now().Add(installIDTTL)}
}

func (c *cache) getInstallToken(owner string) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.installToken[owner]
	if !ok || time.Now().After(e.exp) {
		return "", false
	}
	return e.token, true
}

func (c *cache) setInstallToken(owner, token string, githubExpiry time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.installToken[owner] = tokenEntry{token: token, exp: githubExpiry.Add(-tokenSafetyMargin)}
}

func (c *cache) getPolicy(key string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.policy[key]
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.content, true
}

func (c *cache) setPolicy(key string, content []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy[key] = policyEntry{content: content, exp: time.Now().Add(policyTTL)}
}
