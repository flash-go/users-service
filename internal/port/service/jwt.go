package port

import (
	"context"
	"time"

	"github.com/flash-go/sdk/errors"
)

const JwtServiceTokenAudience = "users-service"
const JwtServiceTokenKeyMinLen = 64 // bytes = 512 bits for HS512 (HMAC-SHA-512) keys

type JwtServicePort interface {
	NewTokens(ctx context.Context, data NewJwtTokenData) (*JwtTokensResult, error)
	NewAccessToken(ctx context.Context, data NewJwtTokenData) (*string, error)
	NewRefreshToken(ctx context.Context, data NewJwtTokenData) (*string, error)
	GetAccessTokenDuration() (time.Duration, error)
	GetRefreshTokenDuration() (time.Duration, error)
	ParseAccessToken(token string) (*ParseJwtTokenResult, error)
	ParseRefreshToken(token string) (*ParseJwtTokenResult, error)
	SetRefreshTokenJtiToCache(ctx context.Context, user uint, jti string, ttl time.Duration) error
	GetRefreshTokenJtiFromCache(ctx context.Context, user uint) (*string, error)
}

type NewJwtTokenData struct {
	User uint
	Role string
	Mfa  bool
}

type ParseJwtTokenResult struct {
	Id       string
	User     uint
	Role     string
	Mfa      bool
	Expires  int64
	Issued   int64
	Issuer   string
	Audience []string
}

type JwtTokensResult struct {
	Access  string
	Refresh string
}

var (
	ErrJwtInvalidToken = errors.New(errors.ErrUnauthorized, "invalid_token")
)
