package adapter

import (
	"context"
	"fmt"
	"time"

	port "github.com/flash-go/users-service/internal/port/adapter/repository"
	"github.com/redis/go-redis/v9"
)

func NewJwtRepositoryAdapter(redis *redis.Client) port.JwtRepositoryAdapterPort {
	return &jwtRepositoryAdapter{redis}
}

type jwtRepositoryAdapter struct {
	redis *redis.Client
}

func (a *jwtRepositoryAdapter) SetRefreshTokenJtiToCache(ctx context.Context, user uint, jti string, ttl time.Duration) error {
	return a.redis.Set(
		ctx,
		fmt.Sprintf("users:user:%d:refresh_token_jti", user),
		jti,
		ttl,
	).Err()
}

func (a *jwtRepositoryAdapter) GetRefreshTokenJtiFromCache(ctx context.Context, user uint) (*string, error) {
	token, err := a.redis.Get(
		ctx,
		fmt.Sprintf("users:user:%d:refresh_token_jti", user),
	).Result()

	if err == redis.Nil {
		return nil, port.ErrJwtRefreshTokenExpired
	} else if err != nil {
		return nil, err
	}

	return &token, nil
}
