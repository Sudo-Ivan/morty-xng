package main

import (
	"container/list"
	"sync"
	"time"
)

// cacheEntry is a fully processed response for a proxified resource.
type cacheEntry struct {
	key         string
	body        []byte
	contentType string
	disposition []byte
	expires     time.Time
	size        int64
}

// responseCache is a small in-memory LRU for static proxified content.
// It is opt-in and bounded by total byte size.
type responseCache struct {
	mu       sync.Mutex
	items    map[string]*list.Element
	order    *list.List // front = most recently used
	maxBytes int64
	used     int64
	ttl      time.Duration
	hits     int64
	misses   int64
}

func newResponseCache(maxBytes int64, ttl time.Duration) *responseCache {
	return &responseCache{
		items:    make(map[string]*list.Element),
		order:    list.New(),
		maxBytes: maxBytes,
		ttl:      ttl,
	}
}

// get returns a cached response body or nil.
func (c *responseCache) get(key string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		c.misses++
		return nil
	}
	entry := el.Value.(*cacheEntry)
	if time.Now().After(entry.expires) {
		c.remove(el)
		c.misses++
		return nil
	}
	c.order.MoveToFront(el)
	c.hits++
	return entry
}

// put stores a response. Entries larger than the whole cache are dropped.
func (c *responseCache) put(key string, body []byte, contentType string, disposition []byte) {
	size := int64(len(body))
	if size > c.maxBytes {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		c.used -= el.Value.(*cacheEntry).size
		c.order.Remove(el)
		delete(c.items, key)
	}

	entry := &cacheEntry{
		key:         key,
		body:        body,
		contentType: contentType,
		disposition: disposition,
		expires:     time.Now().Add(c.ttl),
		size:        size,
	}
	c.items[key] = c.order.PushFront(entry)
	c.used += size

	for c.used > c.maxBytes && c.order.Len() > 0 {
		c.remove(c.order.Back())
	}
}

func (c *responseCache) remove(el *list.Element) {
	entry := el.Value.(*cacheEntry)
	c.used -= entry.size
	delete(c.items, entry.key)
	c.order.Remove(el)
}

// stats returns hits, misses, entry count and used bytes for metrics.
func (c *responseCache) stats() (hits, misses, entries, usedBytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses, int64(c.order.Len()), c.used
}
