package factory

import (
	"strconv"
	"strings"
	"time"

	"github.com/flash-go/users-service/internal/domain/entity"
	"golang.org/x/crypto/bcrypt"
)

func NewUser(data UserData) (*entity.User, error) {
	// Generate hash from password
	passHash, err := bcrypt.GenerateFromPassword([]byte(data.Password+strconv.FormatInt(data.Created.UnixMicro(), 16)), 14)
	if err != nil {
		return nil, err
	}

	// Create user entity
	return &entity.User{
		Username:  strings.ToLower(data.Username),
		Email:     strings.ToLower(data.Email),
		Password:  string(passHash),
		OtpSecret: data.OtpSecret,
		Role:      data.Role,
		Created:   time.Unix(0, data.Created.UnixNano()),
	}, nil
}

type UserData struct {
	Username  string
	Email     string
	Password  string
	Role      entity.Role
	Created   time.Time
	OtpSecret string
}
