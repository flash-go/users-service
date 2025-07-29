package adapter

import (
	"context"
	"fmt"
	"time"

	jwtRepositoryAdapterPort "github.com/flash-go/users-service/internal/port/adapter/repository/jwt"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	RedisClient *redis.Client
}

func New(config *Config) jwtRepositoryAdapterPort.Interface {
	return &adapter{
		redis: config.RedisClient,
	}
}

type adapter struct {
	redis *redis.Client
}

func (a *adapter) SetRefreshTokenJtiToCache(ctx context.Context, user uint, jti string, ttl time.Duration) error {
	return a.redis.Set(
		ctx,
		fmt.Sprintf("users:user:%d:refresh_token_jti", user),
		jti,
		ttl,
	).Err()
}

func (a *adapter) GetRefreshTokenJtiFromCache(ctx context.Context, user uint) (*string, error) {
	token, err := a.redis.Get(
		ctx,
		fmt.Sprintf("users:user:%d:refresh_token_jti", user),
	).Result()

	if err == redis.Nil {
		return nil, jwtRepositoryAdapterPort.ErrRefreshTokenExpired
	} else if err != nil {
		return nil, err
	}

	return &token, nil
}
