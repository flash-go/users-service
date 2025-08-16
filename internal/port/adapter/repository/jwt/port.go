package port

import (
	"context"
	"time"
)

type Interface interface {
	NewSession(ctx context.Context, user uint, device string, session Session, ttl time.Duration) error
	GetSession(ctx context.Context, user uint, device string) (*Session, error)
	UpdateSession(ctx context.Context, user uint, device, jti string, ttl time.Duration) error
	DeleteSession(ctx context.Context, user uint, device string) error
	GetActiveDevices(ctx context.Context, user uint) ([]Device, error)
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
