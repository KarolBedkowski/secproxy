//
// ldap.go
// Copyright (C) 2017 Karol Będkowski
//

package config

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
	"k.prv/secproxy/logging"
)

var logLdap = logging.NewLogger("config.ldap")

//LDAPConfiguration for ldap client
type LDAPConfiguration struct {
	// Enable ldap authenticate
	Enable bool

	// Server - ldap server (host:port)
	Server string
	// User query string; %s is replaced by user login
	// (i.e. cn=%s,ou=users,dc=myorg,dc=com)
	Query string
	// StartTLS enable tls connection
	StartTLS bool
}

func (l *LDAPConfiguration) Validate() error {
	if !l.Enable {
		return nil
	}
	if l.Server == "" {
		return fmt.Errorf("LDAP: missing 'Server' parameter")
	}
	if l.Query == "" {
		return fmt.Errorf("LDAP: missing 'Query' parameter")
	}
	return nil
}

func AuthenticateLdap(login, pass string, g *Globals) (res bool) {
	llog := logLdap.With("login", login)
	conf := g.Config.Ldap
	if !conf.Enable || conf.Server == "" {
		return false
	}

	llog.Debug("LDAP: trying AuthenticateLdap")

	l, err := ldap.Dial("tcp", conf.Server)
	if err != nil {
		llog.With("err", err).
			Warn("LDAP: dial to ldap server %s failed", conf.Server)
		return false
	}
	//l.Debug = true

	defer func() {
		l.Close()
		if e := recover(); e != nil {
			llog.With("err", e).Debug("recovered")
		}
	}()

	if conf.StartTLS {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			llog.With("err", err).
				Warn("LDAP: start tls for ldap server %s failed", conf.Server)
			return false
		}
	}
	query := fmt.Sprintf(conf.Query, login)
	err = l.Bind(query, pass)
	if err != nil {
		llog.With("err", err).Debug("LDAP: authenticate failed")
		return false
	}

	llog.Debug("LDAP: authenticate success")
	return true
}
