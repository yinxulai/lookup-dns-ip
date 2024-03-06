package cache

import "sync"

var mu sync.Mutex
var globalCache map[string]string

func GetCache(id string) (string, bool) {
	value, ok := globalCache[id]
	return value, ok
}

func SetCache(id string, value string) {
	mu.Lock()
	globalCache[id] = value
	mu.Unlock()
}
