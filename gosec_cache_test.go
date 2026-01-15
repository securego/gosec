package gosec

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLRUCache_AddGet(t *testing.T) {
	cache := NewLRUCache[string, int](2)

	cache.Add("one", 1)
	val, ok := cache.Get("one")
	assert.True(t, ok)
	assert.Equal(t, 1, val)

	cache.Add("two", 2)
	val, ok = cache.Get("two")
	assert.True(t, ok)
	assert.Equal(t, 2, val)
}

func TestLRUCache_Miss(t *testing.T) {
	cache := NewLRUCache[string, int](2)

	val, ok := cache.Get("missing")
	assert.False(t, ok)
	assert.Equal(t, 0, val)
}

func TestLRUCache_Eviction(t *testing.T) {
	cache := NewLRUCache[string, int](2)

	cache.Add("one", 1)
	cache.Add("two", 2)

	// Cache is full: [two, one]

	// Access "one" to make it most recently used
	// Cache: [one, two]
	_, ok := cache.Get("one")
	assert.True(t, ok)

	// Add "three", should evict "two" (LRU)
	cache.Add("three", 3)
	// Cache: [three, one]

	val, ok := cache.Get("two")
	assert.False(t, ok, "Expected 'two' to be evicted")
	assert.Equal(t, 0, val)

	val, ok = cache.Get("one")
	assert.True(t, ok, "Expected 'one' to remain")
	assert.Equal(t, 1, val)

	val, ok = cache.Get("three")
	assert.True(t, ok, "Expected 'three' to exist")
	assert.Equal(t, 3, val)
}

func TestLRUCache_UpdateExisting(t *testing.T) {
	cache := NewLRUCache[string, int](2)

	cache.Add("one", 1)
	cache.Add("two", 2)

	// Update "one"
	cache.Add("one", 10)

	val, ok := cache.Get("one")
	assert.True(t, ok)
	assert.Equal(t, 10, val)

	// Ensure updating didn't change size unexpectedly or eviction order incorrectly
	// Cache should be: [one, two] (because "one" was just added/updated)

	// Add "three", should evict "two"
	cache.Add("three", 3)

	_, ok = cache.Get("two")
	assert.False(t, ok, "Expected 'two' to be evicted")

	_, ok = cache.Get("one")
	assert.True(t, ok)
}

func TestGlobalCache_Stress(t *testing.T) {
	// Simple stress test to ensure thread safety (running with -race is ideal)
	// We can't easily assert on race conditions without the race detector,
	// but this ensures no obvious panics or deadlocks.

	const routines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(routines)

	for i := range routines {
		go func(id int) {
			defer wg.Done()
			key := GlobalKey{Kind: 0, Str: fmt.Sprintf("str-%d", id)}
			for j := range iterations {
				GlobalCache.Add(key, j)
				if _, ok := GlobalCache.Get(key); !ok {
					t.Errorf("failed to get key %v", key)
				}
			}
		}(i)
	}
	wg.Wait()
}
