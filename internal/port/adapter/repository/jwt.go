package port

import (
	"context"
	"time"

	"github.com/flash-go/sdk/errors"
)

type JwtRepositoryAdapterPort interface {
	SetRefreshTokenJtiToCache(ctx context.Context, user uint, jti string, ttl time.Duration) error
	GetRefreshTokenJtiFromCache(ctx context.Context, user uint) (*string, error)
}

var (
	ErrJwtRefreshTokenExpired = errors.New(errors.ErrBadRequest, "refresh_token_expired")
)
