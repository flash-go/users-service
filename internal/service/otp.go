package service

import (
	"context"
	"fmt"

	servicePort "github.com/flash-go/users-service/internal/port/service"
	"github.com/pquerna/otp/totp"
)

const otpServiceSecretSize = 15

type OtpServiceConfig struct {
	OtpIssuer string
}

func NewOtpService(config *OtpServiceConfig) servicePort.OtpServicePort {
	return &otpService{
		config.OtpIssuer,
	}
}

type otpService struct {
	otpIssuer string
}

func (s *otpService) GenerateSecret(ctx context.Context, accountName string) (*string, error) {
	// Generate key
	key, err := totp.Generate(
		totp.GenerateOpts{
			Issuer:      s.otpIssuer,
			AccountName: accountName,
			SecretSize:  otpServiceSecretSize,
		},
	)
	if err != nil {
		return nil, err
	}

	// Get secret
	secret := key.Secret()

	return &secret, nil
}

func (s *otpService) GenerateUrl(accountName, secret string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?algorithm=SHA1&digits=6&issuer=%s&period=30&secret=%s",
		s.otpIssuer,
		accountName,
		s.otpIssuer,
		secret,
	)
}

func (s *otpService) ValidateToken(token, secret string) error {
	if !totp.Validate(token, secret) {
		return servicePort.ErrOtpInvalidToken
	}
	return nil
}
