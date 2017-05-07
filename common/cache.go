//
// cache.go
// Copyright (C) Karol Będkowski, 2017
//

package common

import (
	"sync"
	"time"
)

type Cache interface {
	Put(key string, data interface{})
	Get(key string) (data interface{}, ok bool)
}

type cacheItem struct {
	expiredAt int64
	data      interface{}
}

type timedCache struct {
	ttl   int64
	items map[string]cacheItem

	mu sync.Mutex
}

func NewTimedCache(ttl uint) Cache {
	return &timedCache{
		ttl:   int64(ttl),
		items: make(map[string]cacheItem),
	}
}

func (t *timedCache) Put(key string, data interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().Unix()
	t.items[key] = cacheItem{
		expiredAt: now + t.ttl,
		data:      data,
	}
}

func (t *timedCache) Get(key string) (data interface{}, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if item, iok := t.items[key]; iok {
		now := time.Now().Unix()
		if item.expiredAt > now {
			return item.data, true
		}
		// delete expired object
		delete(t.items, key)
	}
	return nil, false
}
