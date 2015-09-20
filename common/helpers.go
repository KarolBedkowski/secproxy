package common

import (
	"k.prv/rpimon/helpers/logging"
	nurl "net/url"
)

// BuildQuery format url query part from pairs key, val
func BuildQuery(pairs ...string) (query string) {
	pairsLen := len(pairs)
	if pairsLen == 0 {
		return ""
	}
	if pairsLen%2 != 0 {
		logging.Warn("helpers.BuildQuery error - wron number of argiments: %v", pairs)
		return ""
	}
	query = "?"
	for idx := 0; idx < pairsLen; idx += 2 {
		query += pairs[idx] + "=" + nurl.QueryEscape(pairs[idx+1])
	}
	return
}

