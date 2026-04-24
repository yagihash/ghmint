package installation

import (
	"sync"
	"time"
)

const (
	installIDTTL      = 60 * time.Minute
	tokenSafetyMargin = 5 * time.Minute
)

type cache struct {
	mu           sync.Mutex
	installIDs   map[string]idEntry
	installToks  map[string]tokEntry
}

type idEntry struct {
	id  int64
	exp time.Time
}

type tokEntry struct {
	token string
	exp   time.Time
}

func newCache() *cache {
	return &cache{
		installIDs:  make(map[string]idEntry),
		installToks: make(map[string]tokEntry),
	}
}

func (c *cache) getInstallID(owner string) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.installIDs[owner]
	if !ok || time.Now().After(e.exp) {
		return 0, false
	}
	return e.id, true
}

func (c *cache) setInstallID(owner string, id int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.installIDs[owner] = idEntry{id: id, exp: time.Now().Add(installIDTTL)}
}

func (c *cache) getToken(owner string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.installToks[owner]
	if !ok || time.Now().After(e.exp) {
		return "", false
	}
	return e.token, true
}

func (c *cache) setToken(owner, token string, githubExpiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.installToks[owner] = tokEntry{token: token, exp: githubExpiry.Add(-tokenSafetyMargin)}
}
