package config

import (
	"golang.org/x/crypto/bcrypt"
	"k.prv/secproxy/logging"
)

var logUsers = logging.NewLogger("config.users")

type (
	User struct {
		Login    string
		Name     string
		Password string
		Role     string
		Active   bool
	}
)

func (u *User) CheckPassword(pass string) (ok bool) {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pass))
	if err == nil {
		return true
	}
	return u.Password == pass
}

func (u *User) UpdatePassword(newPass string) {
	if newPass == "" {
		u.Password = ""
	} else {
		data, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		if err != nil {
			logUsers.With("err", err).
				With("user", u).
				Warn("UpdatePassword error")
		} else {
			u.Password = string(data)
		}
	}
}

func (u *User) Validate() (errors map[string]string) {
	return
}

func (u *User) Clone() (nu *User) {
	return &User{
		u.Login,
		u.Name,
		u.Password,
		u.Role,
		u.Active,
	}
}
