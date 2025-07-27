package main

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/flash-go/sdk/config"
	"github.com/flash-go/sdk/infra"
	"github.com/flash-go/sdk/services/users"
	"github.com/flash-go/sdk/state"
	"github.com/flash-go/sdk/telemetry"
	jwtRepositoryAdapter "github.com/flash-go/users-service/internal/adapter/repository/jwt"
	usersRepositoryAdapter "github.com/flash-go/users-service/internal/adapter/repository/users"
	internalConfig "github.com/flash-go/users-service/internal/config"
	"github.com/flash-go/users-service/internal/migrations"
	servicePort "github.com/flash-go/users-service/internal/port/service"
	service "github.com/flash-go/users-service/internal/service"
	_ "github.com/joho/godotenv/autoload"
)

const (
	adminRoleId   = "admin"
	adminUsername = "admin"
)

var envMap = map[string]string{
	"OTEL_COLLECTOR_GRPC": telemetry.OtelCollectorGrpcOptKey,
	"OTP_ISSUER":          internalConfig.OtpIssuerOptKey,
	"JWT_ACCESS_TTL":      internalConfig.JwtAccessTtlOptKey,
	"JWT_REFRESH_TTL":     internalConfig.JwtRefreshTtlOptKey,
	"JWT_ISSUER":          internalConfig.JwtIssuerOptKey,
	"POSTGRES_HOST":       infra.PostgresHostOptKey,
	"POSTGRES_PORT":       infra.PostgresPortOptKey,
	"POSTGRES_USER":       infra.PostgresUserOptKey,
	"POSTGRES_PASSWORD":   infra.PostgresPasswordOptKey,
	"POSTGRES_DB":         infra.PostgresDbOptKey,
	"REDIS_HOST":          infra.RedisHostOptKey,
	"REDIS_PORT":          infra.RedisPortOptKey,
	"REDIS_PASSWORD":      infra.RedisPasswordOptKey,
	"REDIS_DB":            infra.RedisDbOptKey,
}

func main() {
	// Create state service
	stateService := state.New(os.Getenv("CONSUL_AGENT"))

	// Create config
	cfg := config.New(
		stateService,
		os.Getenv("SERVICE_NAME"),
	)

	// Set KV from env map
	cfg.SetEnvMap(envMap)

	// Create KV JWT access key
	jwtAccessKey := users.NewJwtKey(servicePort.JwtServiceTokenKeyMinLen)
	if err := cfg.Set(
		internalConfig.JwtAccessKeyOptKey,
		jwtAccessKey,
	); err != nil {
		log.Fatalf("failed to create KV [%s]: %v", internalConfig.JwtAccessKeyOptKey, err)
	}

	// Create KV JWT refresh key
	jwtRefreshKey := users.NewJwtKey(servicePort.JwtServiceTokenKeyMinLen)
	if err := cfg.Set(
		internalConfig.JwtRefreshKeyOptKey,
		jwtRefreshKey,
	); err != nil {
		log.Fatalf("failed to create KV [%s]: %v", internalConfig.JwtRefreshKeyOptKey, err)
	}

	// Create KV admin role
	if err := cfg.Set(
		internalConfig.AdminRoleOptKey,
		adminRoleId,
	); err != nil {
		log.Fatalf("failed to create KV [%s]: %v", internalConfig.AdminRoleOptKey, err)
	}

	// Create postgres client and run migrations
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
