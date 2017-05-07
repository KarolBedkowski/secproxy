//
// users.go
// Copyright (C) Karol Będkowski, 2017
//

package proxy

import (
	"hash/adler32"
	"k.prv/secproxy/common"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
)

var logUsers = logging.NewLogger("proxy.users")
var userAuthCache = common.NewTimedCache(30)

// TODO: change
func hashUserPass(login, pass string) string {
	hash := adler32.Checksum([]byte(login + ":" + pass))
	return string(hash)
}

func checkUser(user *config.User, pass string, g *config.Globals) bool {
	if !user.Active {
		return false
	}

	llog := logUsers.With("login", user.Login)
	lph := hashUserPass(user.Login, pass)

	if _, ok := userAuthCache.Get(lph); ok {
		llog.Debug("Proxy: checkUser cache hit")
		return true
	}

	llog.Debug("Proxy: checkUser cache miss; checking standard")

	if user.CheckPassword(pass) {
		userAuthCache.Put(lph, nil)
		return true
	}

	llog.Debug("Proxy: checkUser checking ldap")

	if config.AuthenticateLdap(user.Login, pass, g) {
		userAuthCache.Put(lph, nil)
		return true
	}

	llog.Debug("Proxy: checkUser user authenticate failed")

	return false
}
