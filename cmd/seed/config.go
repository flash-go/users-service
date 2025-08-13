package main

import (
	"github.com/flash-go/sdk/infra"
	"github.com/flash-go/sdk/telemetry"
	internalConfig "github.com/flash-go/users-service/internal/config"
)

const (
	adminRoleId   = "admin"
	adminUsername = "admin"
	adminName     = "admin"
)

var envMap = map[string]string{
	"OTEL_COLLECTOR_GRPC":       telemetry.OtelCollectorGrpcOptKey,
	"OTEL_COLLECTOR_CA_CRT":     telemetry.OtelCollectorCaCrtOptKey,
	"OTEL_COLLECTOR_CLIENT_CRT": telemetry.OtelCollectorClientCrtOptKey,
	"OTEL_COLLECTOR_CLIENT_KEY": telemetry.OtelCollectorClientKeyOptKey,
	"OTP_ISSUER":                internalConfig.OtpIssuerOptKey,
	"JWT_ACCESS_TTL":            internalConfig.JwtAccessTtlOptKey,
	"JWT_REFRESH_TTL":           internalConfig.JwtRefreshTtlOptKey,
	"JWT_ISSUER":                internalConfig.JwtIssuerOptKey,
	"POSTGRES_HOST":             infra.PostgresHostOptKey,
	"POSTGRES_PORT":             infra.PostgresPortOptKey,
	"POSTGRES_USER":             infra.PostgresUserOptKey,
	"POSTGRES_PASSWORD":         infra.PostgresPasswordOptKey,
	"POSTGRES_DB":               infra.PostgresDbOptKey,
	"REDIS_HOST":                infra.RedisHostOptKey,
	"REDIS_PORT":                infra.RedisPortOptKey,
	"REDIS_PASSWORD":            infra.RedisPasswordOptKey,
	"REDIS_DB":                  infra.RedisDbOptKey,
}
