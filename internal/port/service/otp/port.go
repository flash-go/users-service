package port

import (
	"context"
)

type Interface interface {
	GenerateSecret(ctx context.Context, accountName string) (*string, error)
	GenerateUrl(accountName, secret string) string
	ValidateToken(token, secret string) error
}
