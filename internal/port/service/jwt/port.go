package port

import (
	"context"
)

type Interface interface {
	NewTokens(ctx context.Context, data NewJwtTokenData) (*JwtTokensResult, error)
	NewSession(ctx context.Context, user uint, device string, session Session) error
	GetSession(ctx context.Context, user uint, device string) (*Session, error)
	UpdateSession(ctx context.Context, user uint, device, jti string) error
	DeleteSession(ctx context.Context, user uint, device string) error
	GetActiveDevices(ctx context.Context, user uint) ([]Device, error)
	NewAccessToken(ctx context.Context, data NewJwtTokenData) (*string, error)
	NewRefreshToken(ctx context.Context, data NewJwtTokenData) (*string, error)
	ParseAccessToken(token string) (*ParseJwtTokenResult, error)
	ParseRefreshToken(token string) (*ParseJwtTokenResult, error)
}

type Session struct {
	Jti            string
	IssuedAt       string
	Location       string
	Ip             string
	UserAgent      string
	OsFullName     string
	OsName         string
	OsVersion      string
	Platform       string
	Model          string
	BrowserName    string
	BrowserVersion string
	EngineName     string
	EngineVersion  string
}

type Device struct {
	Id      string
	Session Session
}

type NewJwtTokenData struct {
	User   uint
	Role   string
	Mfa    bool
	Device string
}

type ParseJwtTokenResult struct {
	Id       string
	Device   string
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
