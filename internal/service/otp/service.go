package service

import (
	"context"
	"fmt"

	otpServicePort "github.com/flash-go/users-service/internal/port/service/otp"
	"github.com/pquerna/otp/totp"
)

type Config struct {
	OtpIssuer string
}

func New(config *Config) otpServicePort.Interface {
	return &service{
		config.OtpIssuer,
	}
}

type service struct {
	otpIssuer string
}

func (s *service) GenerateSecret(ctx context.Context, accountName string) (*string, error) {
	// Generate key
	key, err := totp.Generate(
		totp.GenerateOpts{
			Issuer:      s.otpIssuer,
			AccountName: accountName,
			SecretSize:  secretSize,
		},
	)
	if err != nil {
		return nil, err
	}

	// Get secret
	secret := key.Secret()

	return &secret, nil
}

func (s *service) GenerateUrl(accountName, secret string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?algorithm=SHA1&digits=6&issuer=%s&period=30&secret=%s",
		s.otpIssuer,
		accountName,
		s.otpIssuer,
		secret,
	)
}

func (s *service) ValidateToken(token, secret string) error {
	if !totp.Validate(token, secret) {
		return otpServicePort.ErrInvalidToken
	}
	return nil
}
