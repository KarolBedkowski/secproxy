package admin

import (
	"encoding/gob"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"k.prv/secproxy/config"
	"k.prv/secproxy/logging"
	"net/http"
	"time"
)

const storesession = "SESSION"

// Sessions settings
const (
	sessionTimestampKey  = "timestamp"
	sessionLoggedUserKey = "USER"
	maxSessionAgeDays    = 31
	maxSessionAge        = time.Duration(24*maxSessionAgeDays) * time.Hour
)

type SessionUser struct {
	Login string
	Role  string
}

var store *sessions.CookieStore
var logSession = logging.NewLogger("admin.session")

func init() {
	gob.Register(&SessionUser{})
}

func NewSessionUser(login, role string) *SessionUser {
	return &SessionUser{
		Login: login,
		Role:  role,
	}
}

// InitSessionStore initialize sessions support
func InitSessionStore(conf *config.AppConfiguration) error {
	if len(conf.AdminPanel.CookieAuthKey) < 32 {
		logSession.Info("Random CookieAuthKey")
		conf.AdminPanel.CookieAuthKey = string(securecookie.GenerateRandomKey(32))
	}
	if len(conf.AdminPanel.CookieEncKey) < 32 {
		logSession.Info("Random CookieEncKey")
		conf.AdminPanel.CookieEncKey = string(securecookie.GenerateRandomKey(32))
	}
	store = sessions.NewCookieStore([]byte(conf.AdminPanel.CookieAuthKey),
		[]byte(conf.AdminPanel.CookieEncKey))

	return nil
}

// ClearSession remove all values and save session
func ClearSession(w http.ResponseWriter, r *http.Request) {
	session := GetSessionStore(w, r)
	session.Values = nil
	session.Save(r, w)
}

// SaveSession - shortcut
func SaveSession(w http.ResponseWriter, r *http.Request) error {
	err := sessions.Save(r, w)
	if err != nil {
		logSession.Error("SaveSession error", "err", err)
	}
	return err
}

// MySession is wrapper over gorilla Session
type MySession struct {
	*sessions.Session
}

// GetLoggerUser return login and permission of logged user
func (session *MySession) GetLoggedUser() (user *SessionUser, ok bool) {
	val := session.Values[sessionLoggedUserKey]
	user, ok = val.(*SessionUser)
	return
}

// SetLoggedUser save logged user information in session
func (s *MySession) SetLoggedUser(user *SessionUser) {
	s.Values[sessionLoggedUserKey] = user
}

// GetSessionStore  for given request
func GetSessionStore(w http.ResponseWriter, r *http.Request) *MySession {
	gsession, _ := store.Get(r, storesession)
	session := &MySession{gsession}
	session.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 86400 * maxSessionAgeDays,
	}
	return session
}

// SessionHandler check validity of session
func SessionHandler(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := GetSessionStore(w, r)
		//		context.Set(r, "session", s)
		if ts, ok := s.Values[sessionTimestampKey]; ok {
			timestamp := time.Unix(ts.(int64), 0)
			now := time.Now()
			if now.Sub(timestamp) < maxSessionAge {
				s.Values[sessionTimestampKey] = now.Unix()
			} else {
				s.Values = nil
			}
			s.Save(r, w)
		}
		//l.Debug("Context: %v", context.GetAll(r))
		h.ServeHTTP(w, r)
	})
}
