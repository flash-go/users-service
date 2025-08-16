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

func (a *adapter) NewSession(ctx context.Context, user uint, device string, session jwtRepositoryAdapterPort.Session, ttl time.Duration) error {
	key := fmt.Sprintf("users:sessions:%d:%s", user, device)
	if err := a.redis.HSet(ctx, key, map[string]interface{}{
		"jti":             session.Jti,
		"issued_at":       session.IssuedAt,
		"location":        session.Location,
		"ip":              session.Ip,
		"user_agent":      session.UserAgent,
		"os_full_name":    session.OsFullName,
		"os_name":         session.OsName,
		"os_version":      session.OsVersion,
		"platform":        session.Platform,
		"model":           session.Model,
		"browser_name":    session.BrowserName,
		"browser_version": session.BrowserVersion,
		"engine_name":     session.EngineName,
		"engine_version":  session.EngineVersion,
	}).Err(); err != nil {
		return err
	}

	if err := a.redis.Expire(ctx, key, ttl).Err(); err != nil {
		return err
	}

	devicesKey := fmt.Sprintf("users:devices:%d", user)
	if err := a.redis.SAdd(ctx, devicesKey, device).Err(); err != nil {
		return err
	}

	return nil
}

func (a *adapter) UpdateSession(ctx context.Context, user uint, device, jti string, ttl time.Duration) error {
	key := fmt.Sprintf("users:sessions:%d:%s", user, device)

	// Update jti
	if err := a.redis.HSet(ctx, key, "jti", jti).Err(); err != nil {
		return err
	}

	// Update ttl
	if err := a.redis.Expire(ctx, key, ttl).Err(); err != nil {
		return err
	}

	return a.redis.HSet(ctx, key, "jti", jti).Err()
}

func (a *adapter) DeleteSession(ctx context.Context, user uint, device string) error {
	sessionKey := fmt.Sprintf("users:sessions:%d:%s", user, device)
	devicesKey := fmt.Sprintf("users:devices:%d", user)

	// Delete session
	if err := a.redis.Del(ctx, sessionKey).Err(); err != nil {
		return err
	}

	// Delete device
	if err := a.redis.SRem(ctx, devicesKey, device).Err(); err != nil {
		return err
	}

	return nil
}

func (a *adapter) GetSession(ctx context.Context, user uint, device string) (*jwtRepositoryAdapterPort.Session, error) {
	key := fmt.Sprintf("users:sessions:%d:%s", user, device)
	data, err := a.redis.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, nil
	}

	return &jwtRepositoryAdapterPort.Session{
		Jti:            data["jti"],
		IssuedAt:       data["issued_at"],
		Location:       data["location"],
		Ip:             data["ip"],
		UserAgent:      data["user_agent"],
		OsFullName:     data["os_full_name"],
		OsName:         data["os_name"],
		OsVersion:      data["os_version"],
		Platform:       data["platform"],
		Model:          data["model"],
		BrowserName:    data["browser_name"],
		BrowserVersion: data["browser_version"],
		EngineName:     data["engine_name"],
		EngineVersion:  data["engine_version"],
	}, nil
}

func (a *adapter) GetActiveDevices(ctx context.Context, user uint) ([]jwtRepositoryAdapterPort.Device, error) {
	devicesKey := fmt.Sprintf("users:devices:%d", user)
	devices, err := a.redis.SMembers(ctx, devicesKey).Result()
	if err != nil {
		return nil, err
	}

	activeDevices := make([]jwtRepositoryAdapterPort.Device, 0, len(devices))

	for _, device := range devices {
		if session, err := a.GetSession(ctx, user, device); err == nil {
			if session == nil {
				// Remove expired device from Set
				_ = a.redis.SRem(ctx, devicesKey, device)
			} else {
				activeDevices = append(
					activeDevices,
					jwtRepositoryAdapterPort.Device{
						Id:      device,
						Session: *session,
					},
				)
			}
		} else {
			return nil, err
		}
	}

	return activeDevices, nil
}
