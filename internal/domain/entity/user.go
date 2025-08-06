package entity

import (
	"strconv"
	"time"

	"github.com/flash-go/sdk/errors"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id        uint
	Created   time.Time
	Username  string
	Email     string
	Password  string
	Name      string
	Role      Role
	Mfa       bool
	OtpSecret string
}

func (u *User) ComparePassword(password string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password+strconv.FormatInt(u.Created.UnixMicro(), 16))); err != nil {
		return ErrUserInvalidCredentials
	}
	return nil
}

var (
	ErrUserInvalidCredentials = errors.New(errors.ErrUnauthorized, "invalid_credentials")
)
