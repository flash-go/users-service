package main

import (
	"context"
	"errors"
	"log"
	"os"

	jwtRepositoryAdapter "github.com/flash-go/users-service/internal/adapter/repository/jwt"
	usersRepositoryAdapter "github.com/flash-go/users-service/internal/adapter/repository/users"
	"github.com/flash-go/users-service/internal/migrations"
	servicePort "github.com/flash-go/users-service/internal/port/service"
	service "github.com/flash-go/users-service/internal/service"

	"github.com/flash-go/sdk/config"
	"github.com/flash-go/sdk/infra"
	"github.com/flash-go/sdk/services/users"
	"github.com/flash-go/sdk/state"

	_ "github.com/joho/godotenv/autoload"
)

const (
	jwtKeySize          = 64 // bytes = 512 bits for HS512 (HMAC-SHA-512) keys
	jwtAccessKeyOptKey  = "/jwt/access/key"
	jwtRefreshKeyOptKey = "/jwt/refresh/key"
	adminRoleOptKey     = "/admin/role"
	adminRoleId         = "admin"
	adminUsername       = "admin"
)

var envMap = map[string]string{
	"OTEL_COLLECTOR_GRPC": "/telemetry/collector/grpc",
	"OTP_ISSUER":          "/otp/issuer",
	"JWT_ACCESS_TTL":      "/jwt/access/ttl",
	"JWT_REFRESH_TTL":     "/jwt/refresh/ttl",
	"JWT_ISSUER":          "/jwt/issuer",
	"POSTGRES_HOST":       "/postgres/host",
	"POSTGRES_PORT":       "/postgres/port",
	"POSTGRES_USER":       "/postgres/user",
	"POSTGRES_PASSWORD":   "/postgres/password",
	"POSTGRES_DB":         "/postgres/db",
	"REDIS_HOST":          "/redis/host",
	"REDIS_PORT":          "/redis/port",
	"REDIS_PASSWORD":      "/redis/password",
	"REDIS_DB":            "/redis/db",
}

func main() {
	// Create state service
	stateService := state.New(os.Getenv("CONSUL_AGENT"))

	// Create config
	cfg := config.New(stateService, os.Getenv("SERVICE_NAME"))

	// Create KV from key map
	for env, key := range envMap {
		if err := cfg.Set(key, os.Getenv(env)); err != nil {
			log.Fatalf("failed to create KV [%s]: %v", key, err)
		}
	}

	// Create KV JWT access key
	jwtAccessKey := users.NewJwtKey(jwtKeySize)
	if err := cfg.Set(jwtAccessKeyOptKey, jwtAccessKey); err != nil {
		log.Fatalf("failed to create KV [%s]: %v", jwtAccessKeyOptKey, err)
	}

	// Create KV JWT refresh key
	jwtRefreshKey := users.NewJwtKey(jwtKeySize)
	if err := cfg.Set(jwtRefreshKeyOptKey, jwtRefreshKey); err != nil {
		log.Fatalf("failed to create KV [%s]: %v", jwtRefreshKeyOptKey, err)
	}

	// Create KV admin role
	if err := cfg.Set(adminRoleOptKey, adminRoleId); err != nil {
		log.Fatalf("failed to create KV [%s]: %v", adminRoleOptKey, err)
	}

	// Create postgres client
	postgresClient := infra.NewPostgresClient(
		&infra.PostgresClientConfig{
			Cfg:        cfg,
			Telemetry:  nil,
			Migrations: migrations.Get(),
		},
	)

	// Create redis client
	redisClient := infra.NewRedisClient(
		&infra.RedisClientConfig{
			Cfg:       cfg,
			Telemetry: nil,
		},
	)

	// Create repository
	jwtRepository := jwtRepositoryAdapter.NewJwtRepositoryAdapter(redisClient)
	usersRepository := usersRepositoryAdapter.NewUsersRepositoryAdapter(postgresClient)

	// Create services
	otpService := service.NewOtpService(
		&service.OtpServiceConfig{
			OtpIssuer: os.Getenv("OTP_ISSUER"),
		},
	)
	jwtService := service.NewJwtService(
		&service.JwtServiceConfig{
			JwtRepository:    jwtRepository,
			JwtAccessExpire:  os.Getenv("JWT_ACCESS_TTL"),
			JwtRefreshExpire: os.Getenv("JWT_REFRESH_TTL"),
			JwtAccessKey:     jwtAccessKey,
			JwtRefreshKey:    jwtRefreshKey,
			JwtIssuer:        os.Getenv("JWT_ISSUER"),
		},
	)
	usersService := service.NewUsersService(
		&service.UsersServiceConfig{
			UsersRepository: usersRepository,
			OtpService:      otpService,
			JwtService:      jwtService,
		},
	)

	// Create admin role
	if _, err := usersService.CreateRole(
		context.Background(),
		&servicePort.CreateRoleData{
			Id:   adminRoleId,
			Name: os.Getenv("ADMIN_ROLE_NAME"),
		},
	); err != nil && !errors.Is(err, servicePort.ErrUserRoleExistId) {
		log.Printf("failed to create admin role: %v\n", err)
	}

	// Create admin user
	if _, err := usersService.CreateUser(
		context.Background(),
		&servicePort.CreateUserData{
			Username: adminUsername,
			Email:    os.Getenv("ADMIN_EMAIL"),
			Password: os.Getenv("ADMIN_PASSWORD"),
			Role:     adminRoleId,
		},
	); err != nil && !errors.Is(err, servicePort.ErrUserExistUsername) && !errors.Is(err, servicePort.ErrUserExistEmail) {
		log.Printf("failed to create admin user: %v\n", err)
	}
}
