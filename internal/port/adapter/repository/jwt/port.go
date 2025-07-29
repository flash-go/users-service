package port

import (
	"context"
	"time"
)

type Interface interface {
	SetRefreshTokenJtiToCache(ctx context.Context, user uint, jti string, ttl time.Duration) error
	GetRefreshTokenJtiFromCache(ctx context.Context, user uint) (*string, error)
}
