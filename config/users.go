package config

import (
	"golang.org/x/crypto/bcrypt"
	"k.prv/secproxy/logging"
)

var logUsers = logging.NewLogger("config.users")

// User in system
type User struct {
	Login    string
	Name     string
	Password string
	Role     string
	Active   bool
}

// CheckPassword check is pass is equal to hash in User object
func (u *User) CheckPassword(pass string) (ok bool) {
	if u.Password == "" && pass == "" {
		return true
	}
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pass))
	return err == nil
}

// UpdatePassword in user object; password is hashed
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

// Validate user structure; returns map of errors
func (u *User) Validate() (errors map[string]string) {
	errors = make(map[string]string)
	if u.Name == "" {
		errors["Name"] = "missing value"
	}
	if u.Role == "" {
		errors["Role"] = "missing role"
	}
	return
}

// Clone user structure
func (u *User) Clone() (nu *User) {
	return &User{
		u.Login,
		u.Name,
		u.Password,
		u.Role,
		u.Active,
	}
}
