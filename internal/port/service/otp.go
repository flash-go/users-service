package port

import (
	"context"

	"github.com/flash-go/sdk/errors"
)

type OtpServicePort interface {
	GenerateSecret(ctx context.Context, accountName string) (*string, error)
	GenerateUrl(accountName, secret string) string
	ValidateToken(token, secret string) error
}

var (
	ErrOtpInvalidToken = errors.New(errors.ErrBadRequest, "invalid_token")
)
