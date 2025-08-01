package main

// @title		users-service
// @version		1.0
// @BasePath	/

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

import (
	"log"
	"os"
	"strconv"

	// Framework
	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/server"

	// SDK
	"github.com/flash-go/sdk/config"
	"github.com/flash-go/sdk/errors"
	"github.com/flash-go/sdk/infra"
	"github.com/flash-go/sdk/logger"
	"github.com/flash-go/sdk/state"
	"github.com/flash-go/sdk/telemetry"

	// Implementations
	httpUsersHandlerAdapterImpl "github.com/flash-go/users-service/internal/adapter/handler/users/http"
	jwtRepositoryAdapterImpl "github.com/flash-go/users-service/internal/adapter/repository/jwt"
	usersRepositoryAdapterImpl "github.com/flash-go/users-service/internal/adapter/repository/users"
	jwtServiceImpl "github.com/flash-go/users-service/internal/service/jwt"
	otpServiceImpl "github.com/flash-go/users-service/internal/service/otp"
	usersServiceImpl "github.com/flash-go/users-service/internal/service/users"

	// Other
	_ "github.com/flash-go/users-service/docs"
	internalConfig "github.com/flash-go/users-service/internal/config"
	_ "github.com/joho/godotenv/autoload"
)

func main() {
	// Create state service
	stateService := state.New(os.Getenv("CONSUL_AGENT"))

	// Create config
	cfg := config.New(
		stateService,
		os.Getenv("SERVICE_NAME"),
	)

	// Create logger service
	loggerService := logger.NewConsole()

	// Convert log level to int
	logLevel, err := strconv.Atoi(os.Getenv("LOG_LEVEL"))
	if err != nil {
		log.Fatalf("invalid log level")
	}

	// Set log level
	loggerService.SetLevel(logLevel)

	// Create telemetry service
	telemetryService := telemetry.NewGrpc(cfg)

	// Collect metrics
	telemetryService.CollectGoRuntimeMetrics(collectGoRuntimeMetricsTimeout)

	// Create postgres client without migrations
	postgresClient := infra.NewPostgresClient(
		&infra.PostgresClientConfig{
			Cfg:        cfg,
			Telemetry:  telemetryService,
			Migrations: nil,
		},
	)

	// Create redis client
	redisClient := infra.NewRedisClient(
		&infra.RedisClientConfig{
			Cfg:       cfg,
			Telemetry: telemetryService,
		},
	)

	// Create http server
	httpServer := server.New()

	// Use telemetry service
	httpServer.UseTelemetry(telemetryService)

	// Use logger service
	httpServer.UseLogger(loggerService)

	// Use state service
	httpServer.UseState(stateService)

	// Use Swagger
	httpServer.UseSwagger()

	// Set error response status map
	httpServer.SetErrorResponseStatusMap(
		&server.ErrorResponseStatusMap{
			errors.ErrBadRequest:   400,
			errors.ErrUnauthorized: 401,
			errors.ErrForbidden:    403,
			errors.ErrNotFound:     404,
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
			OtpIssuer: cfg.Get(internalConfig.OtpIssuerOptKey),
		},
	)
	jwtService := jwtServiceImpl.New(
		&jwtServiceImpl.Config{
			JwtRepository:    jwtRepository,
			JwtAccessExpire:  cfg.Get(internalConfig.JwtAccessTtlOptKey),
			JwtRefreshExpire: cfg.Get(internalConfig.JwtRefreshTtlOptKey),
			JwtAccessKey:     cfg.Get(internalConfig.JwtAccessKeyOptKey),
			JwtRefreshKey:    cfg.Get(internalConfig.JwtRefreshKeyOptKey),
			JwtIssuer:        cfg.Get(internalConfig.JwtIssuerOptKey),
		},
	)
	usersService := usersServiceImpl.New(
		&usersServiceImpl.Config{
			UsersRepository: usersRepository,
			OtpService:      otpService,
			JwtService:      jwtService,
		},
	)

	// Create handlers
	usersHandler := httpUsersHandlerAdapterImpl.New(
		&httpUsersHandlerAdapterImpl.Config{
			UsersService: usersService,
		},
	)

	// Get admin role
	adminRole := cfg.Get(internalConfig.AdminRoleOptKey)

	// Add routes
	httpServer.
		// Users roles

		// Create user role (admin)
		AddRoute(
			http.MethodPost,
			"/admin/users/roles",
			usersHandler.AdminCreateRole,
			usersHandler.AuthMiddleware(true, adminRole),
		).
		// Filter users roles (admin)
		AddRoute(
			http.MethodPost,
			"/admin/users/roles/filter",
			usersHandler.AdminFilterRoles,
			usersHandler.AuthMiddleware(true, adminRole),
		).
		// Delete user role (admin)
		AddRoute(
			http.MethodDelete,
			"/admin/users/roles/{id}",
			usersHandler.AdminDeleteRole,
			usersHandler.AuthMiddleware(true, adminRole),
		).
		// Update user role (admin)
		AddRoute(
			http.MethodPatch,
			"/admin/users/roles/{id}",
			usersHandler.AdminUpdateRole,
			usersHandler.AuthMiddleware(true, adminRole),
		).

		// Users

		// Create user (admin)
		AddRoute(
			http.MethodPost,
			"/admin/users",
			usersHandler.AdminCreateUser,
			usersHandler.AuthMiddleware(true, adminRole),
		).
		// Filter users (admin)
		AddRoute(
			http.MethodPost,
			"/admin/users/filter",
			usersHandler.AdminFilterUsers,
			usersHandler.AuthMiddleware(true, adminRole),
		).
		// Delete user (admin)
		AddRoute(
			http.MethodDelete,
			"/admin/users/{id}",
			usersHandler.AdminDeleteUser,
			usersHandler.AuthMiddleware(true, adminRole),
		).
		// User profile
		AddRoute(
			http.MethodGet,
			"/users/profile",
			usersHandler.GetProfile,
			usersHandler.AuthMiddleware(true),
		).

		// Auth

		// User auth 2FA validate
		AddRoute(
			http.MethodPost,
			"/users/auth/2fa/validate",
			usersHandler.Auth2faValidate,
			usersHandler.AuthMiddleware(false),
		).
		// User auth 2FA settings
		AddRoute(
			http.MethodPost,
			"/users/auth/2fa/settings",
			usersHandler.Auth2faSettings,
			usersHandler.AuthMiddleware(true),
		).
		// User auth 2FA enable
		AddRoute(
			http.MethodPost,
			"/users/auth/2fa/enable",
			usersHandler.Auth2faEnable,
			usersHandler.AuthMiddleware(true),
		).
		// User auth 2FA disable
		AddRoute(
			http.MethodPost,
			"/users/auth/2fa/disable",
			usersHandler.Auth2faDisable,
			usersHandler.AuthMiddleware(true),
		).
		// User auth
		AddRoute(
			http.MethodPost,
			"/users/auth",
			usersHandler.Auth,
		).
		// Renew JWT token
		AddRoute(
			http.MethodPost,
			"/users/auth/token/renew",
			usersHandler.AuthTokenRenew,
		).
		// Validate JWT token
		AddRoute(
			http.MethodPost,
			"/users/auth/token/validate",
			usersHandler.AuthTokenValidate,
		)

	// Convert service port to int
	servicePort, err := strconv.Atoi(os.Getenv("SERVICE_PORT"))
	if err != nil || servicePort <= 0 {
		log.Fatalf("invalid service port")
	}

	// Register service
	if err := httpServer.RegisterService(
		os.Getenv("SERVICE_NAME"),
		os.Getenv("SERVICE_HOST"),
		servicePort,
	); err != nil {
		loggerService.Log().Err(err).Send()
	}

	// Convert server port to int
	serverPort, err := strconv.Atoi(os.Getenv("SERVER_PORT"))
	if err != nil || serverPort <= 0 {
		log.Fatal("invalid server port")
	}

	// Listen http server
	if err := <-httpServer.Listen(
		os.Getenv("SERVER_HOST"),
		serverPort,
	); err != nil {
		loggerService.Log().Err(err).Send()
	}
}
