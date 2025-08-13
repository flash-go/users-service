package main

import (
	"os"

	// SDK
	"github.com/flash-go/sdk/config"
	"github.com/flash-go/sdk/infra"
	"github.com/flash-go/sdk/state"

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

	// Create postgres client and run mirgations
	infra.NewPostgresClient(
		&infra.PostgresClientConfig{
			Cfg:        cfg,
			Telemetry:  nil,
			Migrations: migrations.Get(),
		},
	)
}
