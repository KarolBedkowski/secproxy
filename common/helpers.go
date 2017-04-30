package common

import (
	"k.prv/secproxy/logging"
	nurl "net/url"
	"os"
)

// BuildQuery format url query part from pairs key, val
func BuildQuery(pairs ...string) (query string) {
	pairsLen := len(pairs)
	if pairsLen == 0 {
		return ""
	}
	if pairsLen%2 != 0 {
		logging.Warn("BuildQuery: error - wrong number of arguments: %+v", pairs)
		return ""
	}
	query = "?"
	for idx := 0; idx < pairsLen; idx += 2 {
		query += pairs[idx] + "=" + nurl.QueryEscape(pairs[idx+1])
	}
	return
}

func FileExists(path string) (exists bool) {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

func DirExists(path string) (exists bool) {
	stat, err := os.Stat(path)
	if err == nil {
		return stat.IsDir()
	}
	return false
}
