package collector

import (
	"context"
	"sync"
)

type cachedResult struct {
	data []byte
	err  error
}

// CachedCollector wraps any Collector and caches command/file results.
// Identical commands or file reads are executed only once.
type CachedCollector struct {
	inner    Collector
	execMu   sync.Mutex
	execCache map[string]cachedResult
	fileMu   sync.Mutex
	fileCache map[string]cachedResult
}

// NewCachedCollector wraps an existing collector with a command cache.
func NewCachedCollector(inner Collector) *CachedCollector {
	return &CachedCollector{
		inner:     inner,
		execCache: make(map[string]cachedResult),
		fileCache: make(map[string]cachedResult),
	}
}

func (c *CachedCollector) Exec(ctx context.Context, cmd string) ([]byte, error) {
	c.execMu.Lock()
	if cached, ok := c.execCache[cmd]; ok {
		c.execMu.Unlock()
		return cached.data, cached.err
	}
	c.execMu.Unlock()

	data, err := c.inner.Exec(ctx, cmd)

	c.execMu.Lock()
	c.execCache[cmd] = cachedResult{data: data, err: err}
	c.execMu.Unlock()

	return data, err
}

func (c *CachedCollector) ReadFile(ctx context.Context, path string) ([]byte, error) {
	c.fileMu.Lock()
	if cached, ok := c.fileCache[path]; ok {
		c.fileMu.Unlock()
		return cached.data, cached.err
	}
	c.fileMu.Unlock()

	data, err := c.inner.ReadFile(ctx, path)

	c.fileMu.Lock()
	c.fileCache[path] = cachedResult{data: data, err: err}
	c.fileMu.Unlock()

	return data, err
}

func (c *CachedCollector) Platform() Platform { return c.inner.Platform() }
func (c *CachedCollector) Target() string     { return c.inner.Target() }
func (c *CachedCollector) Close() error       { return c.inner.Close() }

// Stats returns cache hit statistics.
func (c *CachedCollector) Stats() (execCached, fileCached int) {
	c.execMu.Lock()
	execCached = len(c.execCache)
	c.execMu.Unlock()
	c.fileMu.Lock()
	fileCached = len(c.fileCache)
	c.fileMu.Unlock()
	return
}
