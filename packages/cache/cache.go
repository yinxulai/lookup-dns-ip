package cache

import "sync"

var mu sync.Mutex
var globalCache = make(map[string]string)

func GetCache(id string) (string, bool) {
	value, ok := globalCache[id]

	mu.Lock()
	// 查一次就删掉
	delete(globalCache, id)
	mu.Unlock()

	return value, ok
}

func SetCache(id string, value string) {
	mu.Lock()
	globalCache[id] = value
	mu.Unlock()
}
