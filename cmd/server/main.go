package main

// @title		users-service
// @version		1.0
// @BasePath	/

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

import (
	"os"

	// Framework
	//
	// Core of the Flash Framework. Contains the fundamental components of
	// the application.

	"github.com/flash-go/flash/http"
	"github.com/flash-go/flash/http/server"

	// SDK
	//
	// A high-level software development toolkit based on the Flash Framework
	// for building highly efficient and fault-tolerant applications.

	"github.com/flash-go/sdk/config"
	"github.com/flash-go/sdk/errors"
	"github.com/flash-go/sdk/infra"
	"github.com/flash-go/sdk/logger"
	"github.com/flash-go/sdk/state"
	"github.com/flash-go/sdk/telemetry"

	// Implementations

	//// Handlers
	httpUsersHandlerAdapterImpl "github.com/flash-go/users-service/internal/adapter/handler/users/http"

	//// Repository
	jwtRepositoryAdapterImpl "github.com/flash-go/users-service/internal/adapter/repository/jwt"
	usersRepositoryAdapterImpl "github.com/flash-go/users-service/internal/adapter/repository/users"

	//// Services
	jwtServiceImpl "github.com/flash-go/users-service/internal/service/jwt"
	otpServiceImpl "github.com/flash-go/users-service/internal/service/otp"
	usersServiceImpl "github.com/flash-go/users-service/internal/service/users"

	// Config
	internalConfig "github.com/flash-go/users-service/internal/config"

	// Other
	_ "github.com/flash-go/users-service/docs"
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

	// Create logger service
	loggerService := logger.NewConsole()

	// Set log level
	loggerService.SetLevel(config.GetEnvInt("LOG_LEVEL"))

	// Create telemetry service
	telemetryService := telemetry.NewSecureGrpc(cfg)

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
			usersHandler.AuthMiddleware(
				httpUsersHandlerAdapterImpl.WithAuthRolesOption(adminRole),
			),
		).
		// Filter users roles (admin)
		AddRoute(
			http.MethodPost,
			"/admin/users/roles/filter",
			usersHandler.AdminFilterRoles,
			usersHandler.AuthMiddleware(
				httpUsersHandlerAdapterImpl.WithAuthRolesOption(adminRole),
			),
		).
		// Delete user role (admin)
		AddRoute(
			http.MethodDelete,
			"/admin/users/roles/{id}",
			usersHandler.AdminDeleteRole,
			usersHandler.AuthMiddleware(
				httpUsersHandlerAdapterImpl.WithAuthRolesOption(adminRole),
			),
		).
		// Update user role (admin)
		AddRoute(
			http.MethodPatch,
			"/admin/users/roles/{id}",
			usersHandler.AdminUpdateRole,
			usersHandler.AuthMiddleware(
				httpUsersHandlerAdapterImpl.WithAuthRolesOption(adminRole),
			),
		).

		// Users

		// Create user (admin)
		AddRoute(
			http.MethodPost,
			"/admin/users",
			usersHandler.AdminCreateUser,
			usersHandler.AuthMiddleware(
				httpUsersHandlerAdapterImpl.WithAuthRolesOption(adminRole),
			),
		).
		// Filter users (admin)
		AddRoute(
			http.MethodPost,
			"/admin/users/filter",
			usersHandler.AdminFilterUsers,
			usersHandler.AuthMiddleware(
				httpUsersHandlerAdapterImpl.WithAuthRolesOption(adminRole),
			),
		).
		// Delete user (admin)
		AddRoute(
			http.MethodDelete,
			"/admin/users/{id}",
			usersHandler.AdminDeleteUser,
			usersHandler.AuthMiddleware(
				httpUsersHandlerAdapterImpl.WithAuthRolesOption(adminRole),
			),
		).
		// User profile
		AddRoute(
			http.MethodGet,
			"/users/profile",
			usersHandler.GetProfile,
			usersHandler.AuthMiddleware(),
		).

		// Auth

		// User auth 2FA validate
		AddRoute(
			http.MethodPost,
			"/users/auth/2fa/validate",
			usersHandler.Auth2faValidate,
			usersHandler.AuthMiddleware(
				httpUsersHandlerAdapterImpl.WithoutAuthMfaOption(),
			),
		).
		// User auth 2FA settings
		AddRoute(
			http.MethodPost,
			"/users/auth/2fa/settings",
			usersHandler.Auth2faSettings,
			usersHandler.AuthMiddleware(),
		).
		// User auth 2FA enable
		AddRoute(
			http.MethodPost,
			"/users/auth/2fa/enable",
			usersHandler.Auth2faEnable,
			usersHandler.AuthMiddleware(),
		).
		// User auth 2FA disable
		AddRoute(
			http.MethodPost,
			"/users/auth/2fa/disable",
			usersHandler.Auth2faDisable,
			usersHandler.AuthMiddleware(),
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
		).
		// Logout current device
		AddRoute(
			http.MethodPost,
			"/users/auth/logout",
			usersHandler.AuthLogout,
			usersHandler.AuthMiddleware(),
		).
		// Logout all devices
		AddRoute(
			http.MethodPost,
			"/users/auth/logout/all",
			usersHandler.AuthLogoutAll,
			usersHandler.AuthMiddleware(),
		).
		// Logout target device
		AddRoute(
			http.MethodPost,
			"/users/auth/logout/device",
			usersHandler.AuthLogoutDevice,
			usersHandler.AuthMiddleware(),
		).
		// Active devices
		AddRoute(
			http.MethodGet,
			"/users/auth/devices",
			usersHandler.AuthDevices,
			usersHandler.AuthMiddleware(),
		)

	// Register service
	if err := httpServer.RegisterService(
		os.Getenv("SERVICE_NAME"),
		os.Getenv("SERVICE_HOST"),
		config.GetEnvInt("SERVICE_PORT"),
	); err != nil {
		loggerService.Log().Err(err).Send()
	}

	// Listen http server
	if err := <-httpServer.Listen(
		os.Getenv("SERVER_HOST"),
		config.GetEnvInt("SERVER_PORT"),
	); err != nil {
		loggerService.Log().Err(err).Send()
	}
}
