//
// ldap.go
// Copyright (C) 2017 Karol Będkowski

package config

import (
	"crypto/tls"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/ldap.v2"
	"k.prv/secproxy/logging"
	"time"
)

var logLdap = logging.NewLogger("config.ldap")

// metrics
var (
	ldapReqDur = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Namespace: "secproxy",
			Subsystem: "ldap",
			Name:      "request_duration_seconds",
			Help:      "LDAP requests latencies in seconds",
		},
	)
	ldapReqCnt = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "secproxy",
			Subsystem: "ldap",
			Name:      "requests_total",
			Help:      "Total number of LDAP requests by status.",
		},
		[]string{"status"},
	)
)

func init() {
	prometheus.MustRegister(ldapReqDur)
	prometheus.MustRegister(ldapReqCnt)
}

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

	start := time.Now()

	l, err := ldap.Dial("tcp", conf.Server)
	if err != nil {
		llog.With("err", err).
			Warn("LDAP: dial to ldap server %s failed", conf.Server)
		ldapReqCnt.WithLabelValues("failed").Inc()
		return false
	}
	//l.Debug = true

	defer func() {
		l.Close()
		elapsed := float64(time.Since(start)) / float64(time.Second)
		ldapReqDur.Observe(elapsed)
	}()

	if conf.StartTLS {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			llog.With("err", err).
				Warn("LDAP: start tls for ldap server %s failed", conf.Server)
			ldapReqCnt.WithLabelValues("failed").Inc()
			return false
		}
	}
	query := fmt.Sprintf(conf.Query, login)
	err = l.Bind(query, pass)
	if err != nil {
		llog.With("err", err).Debug("LDAP: authenticate failed")
		ldapReqCnt.WithLabelValues("success").Inc()
		return false
	}

	llog.Debug("LDAP: authenticate success")
	ldapReqCnt.WithLabelValues("success").Inc()
	return true
}
