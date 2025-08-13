package main

import (
	"context"
	"errors"
	"log"
	"os"

	// SDK
	"github.com/flash-go/sdk/config"
	"github.com/flash-go/sdk/infra"
	"github.com/flash-go/sdk/services/users"
	"github.com/flash-go/sdk/state"

	// Implementations
	jwtRepositoryAdapterImpl "github.com/flash-go/users-service/internal/adapter/repository/jwt"
	usersRepositoryAdapterImpl "github.com/flash-go/users-service/internal/adapter/repository/users"
	jwtServiceImpl "github.com/flash-go/users-service/internal/service/jwt"
	otpServiceImpl "github.com/flash-go/users-service/internal/service/otp"
	usersServiceImpl "github.com/flash-go/users-service/internal/service/users"

	// Ports
	jwtServicePort "github.com/flash-go/users-service/internal/port/service/jwt"
	usersServicePort "github.com/flash-go/users-service/internal/port/service/users"

	// Config
	internalConfig "github.com/flash-go/users-service/internal/config"

	// Other
	"github.com/flash-go/users-service/internal/migrations"
	_ "github.com/joho/godotenv/autoload"
)

func main() {
	// Create state service
	stateService := state.NewWithSecureAuth(
		&state.SecureAuthConfig{
			Address:            os.Getenv("CONSUL_ADDR"),
			CAPem:              config.GetEnvBase64("CONSUL_CA_CRT"),
			CertPEM:            config.GetEnvBase64("CONSUL_CLIENT_CRT"),
			KeyPEM:             config.GetEnvBase64("CONSUL_CLIENT_KEY"),
			InsecureSkipVerify: config.GetEnvBool("CONSUL_INSECURE_SKIP_VERIFY"),
			Token:              os.Getenv("CONSUL_TOKEN"),
		},
	)

	// Create config
	cfg := config.New(
		stateService,
		os.Getenv("SERVICE_NAME"),
	)

	// Set KV from env map
	cfg.SetEnvMap(envMap)

	// Create KV JWT access key
	jwtAccessKey := users.NewJwtKey(jwtServicePort.TokenKeyMinLen)
	if err := cfg.Set(
		internalConfig.JwtAccessKeyOptKey,
		jwtAccessKey,
	); err != nil {
		log.Fatalf("failed to create KV [%s]: %v", internalConfig.JwtAccessKeyOptKey, err)
	}

	// Create KV JWT refresh key
	jwtRefreshKey := users.NewJwtKey(jwtServicePort.TokenKeyMinLen)
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
	jwtRepository := jwtRepositoryAdapterImpl.New(
		&jwtRepositoryAdapterImpl.Config{
			RedisClient: redisClient,
		},
	)
	usersRepository := usersRepositoryAdapterImpl.New(
		&usersRepositoryAdapterImpl.Config{
			PostgresClient: postgresClient,
		},
	)

	// Create services
	otpService := otpServiceImpl.New(
		&otpServiceImpl.Config{
			OtpIssuer: os.Getenv("OTP_ISSUER"),
		},
	)
	jwtService := jwtServiceImpl.New(
		&jwtServiceImpl.Config{
			JwtRepository:    jwtRepository,
			JwtAccessExpire:  os.Getenv("JWT_ACCESS_TTL"),
			JwtRefreshExpire: os.Getenv("JWT_REFRESH_TTL"),
			JwtAccessKey:     jwtAccessKey,
			JwtRefreshKey:    jwtRefreshKey,
			JwtIssuer:        os.Getenv("JWT_ISSUER"),
		},
	)
	usersService := usersServiceImpl.New(
		&usersServiceImpl.Config{
			UsersRepository: usersRepository,
			OtpService:      otpService,
			JwtService:      jwtService,
		},
	)

	// Create admin role
	if _, err := usersService.CreateRole(
		context.Background(),
		&usersServicePort.CreateRoleData{
			Id:   adminRoleId,
			Name: os.Getenv("ADMIN_ROLE_NAME"),
		},
	); err != nil && !errors.Is(err, usersServicePort.ErrRoleExistId) {
		log.Printf("failed to create admin role: %v\n", err)
	}

	// Create admin user
	if _, err := usersService.CreateUser(
		context.Background(),
		&usersServicePort.CreateUserData{
			Username: adminUsername,
			Email:    os.Getenv("ADMIN_EMAIL"),
			Password: os.Getenv("ADMIN_PASSWORD"),
			Name:     adminName,
			Role:     adminRoleId,
		},
	); err != nil && !errors.Is(err, usersServicePort.ErrExistUsername) && !errors.Is(err, usersServicePort.ErrExistEmail) {
		log.Printf("failed to create admin user: %v\n", err)
	}
}
