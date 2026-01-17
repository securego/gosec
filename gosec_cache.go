package gosec

import (
	"container/list"
	"regexp"
	"sync"
)

// GlobalCache is a shared LRU cache for expensive operations (Regex matching, Entropy analysis).
var GlobalCache = NewLRUCache[GlobalKey, any](1 << 16)

// Cache kind constants for GlobalKey.Kind.
const (
	CacheKindRegex         = iota // Regex match result
	CacheKindEntropy              // Entropy analysis result
	CacheKindSecretPattern        // Secret pattern match result
)

// GlobalKey is a zero-allocation key for the GlobalCache.
type GlobalKey struct {
	Kind  int            // Use CacheKind* constants
	Regex *regexp.Regexp // Populated for Regex and (optionally) SecretPattern
	Str   string         // Populated for all
}

// LRUCache is a simple thread-safe generic LRU cache.
type LRUCache[K comparable, V any] struct {
	capacity  int
	items     map[K]*list.Element
	evictList *list.List
	lock      sync.Mutex
}

type entry[K comparable, V any] struct {
	key   K
	value V
}

// NewLRUCache creates a new thread-safe LRU cache with the given capacity.
func NewLRUCache[K comparable, V any](capacity int) *LRUCache[K, V] {
	return &LRUCache[K, V]{
		capacity:  capacity,
		items:     make(map[K]*list.Element),
		evictList: list.New(),
	}
}

func (c *LRUCache[K, V]) Get(key K) (V, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	var zero V
	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		return ent.Value.(*entry[K, V]).value, true
	}
	return zero, false
}

func (c *LRUCache[K, V]) Add(key K, value V) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		ent.Value.(*entry[K, V]).value = value
		return
	}

	ent := &entry[K, V]{key, value}
	element := c.evictList.PushFront(ent)
	c.items[key] = element

	if c.evictList.Len() > c.capacity {
		c.removeOldest()
	}
}

func (c *LRUCache[K, V]) removeOldest() {
	ent := c.evictList.Back()
	if ent != nil {
		c.evictList.Remove(ent)
		delete(c.items, ent.Value.(*entry[K, V]).key)
	}
}

// RegexMatch returns the result of re.MatchString(s), using GlobalCache to store previous results.
func RegexMatch(re *regexp.Regexp, s string) bool {
	key := GlobalKey{Kind: CacheKindRegex, Regex: re, Str: s}
	if val, ok := GlobalCache.Get(key); ok {
		return val.(bool)
	}
	res := re.MatchString(s)
	GlobalCache.Add(key, res)
	return res
}
