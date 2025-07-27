package main

import (
	"os"

	"github.com/flash-go/users-service/internal/migrations"

	"github.com/flash-go/sdk/config"
	"github.com/flash-go/sdk/infra"
	"github.com/flash-go/sdk/state"

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

	// Create postgres client and run mirgations
	infra.NewPostgresClient(
		&infra.PostgresClientConfig{
			Cfg:        cfg,
			Telemetry:  nil,
			Migrations: migrations.Get(),
		},
	)
}
