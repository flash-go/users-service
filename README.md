# users-service

Microservice written in Go for managing authorization and authentication of users with JWT and OTP support, based on the [Flash Framework](https://github.com/flash-go/flash) with Hexagonal Architecture.

## Features

- Support for user and role management.
- JWT token support 
    - Support for access and refresh tokens using HS512 (HMAC-SHA-512).
    - Refresh token invalidation based on JTI + Redis.
    - Protection against algorithm substitution attacks (e.g., none or RS256).
    - Validation of standard claims and time-skew compensation.
    - Configurable TTL for access and refresh tokens.
    - External API for parsing and validating access tokens.
- 2FA support
    - Uses TOTP (RFC 6238) with HMAC-SHA1.
    - Enable/disable with additional password verification.
    - Supports Google Authenticator, 1Password, etc.
    - Configurable Issuer name for authenticator apps.
    - JWT tokens with 2FA flag to restrict access to operations.
- Observability
    - Tracing and metrics via OpenTelemetry.
    - Logging via zerolog.
- Consul support for flexible configuration and service discovery.
- Swagger/OpenAPI documentation.
- Support HTTP transport.

## Setup

### 1. Install Task

```
go install github.com/go-task/task/v3/cmd/task@latest
```

### 2. Create .env files

```
task env
```

### 3. Setup .env.server

| Environment Variable | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| CONSUL_AGENT         | Full address (host:port) of the Consul agent (e.g., `localhost:8500`).      |
| SERVICE_NAME         | Name used to register the service in Consul.                                |
| SERVICE_HOST         | Host address under which the service is accessible for Consul registration. |
| SERVICE_PORT         | Port number under which the service is accessible for Consul registration.  |
| SERVER_HOST          | Host address the HTTP server should bind to (e.g., `0.0.0.0`).              |
| SERVER_PORT          | Port number the HTTP server should listen on (e.g., `8080`).                |
| LOG_LEVEL            | Logging level. See the log level table for details.                         |

#### Log Levels

| Level    | Value  | Description                                                                            |
|----------|--------|----------------------------------------------------------------------------------------|
| Trace    | -1     | Fine-grained debugging information, typically only enabled in development.             |
| Debug    | 0      | Detailed debugging information helpful during development and debugging.               |
| Info     | 1      | General operational entries about what's going on inside the application.              |
| Warn     | 2      | Indications that something unexpected happened, but the application continues to work. |
| Error    | 3      | Errors that need attention but do not stop the application.                            |
| Fatal    | 4      | Critical errors causing the application to terminate.                                  |
| Panic    | 5      | Severe errors that will cause a panic; useful for debugging crashes.                   |
| NoLevel  | 6      | No level specified; used when level is not explicitly set.                             |
| Disabled | 7      | Logging is turned off entirely.                                                        |

### 4. Setup .env.migrate

| Environment Variable | Description                                                                           |
|----------------------|---------------------------------------------------------------------------------------|
| CONSUL_AGENT         | Full address (host:port) of the Consul agent (e.g., `localhost:8500`).                |
| SERVICE_NAME         | The name of the service in Consul used to retrieve database connection configuration. |

### 5. Setup .env.seed

| Environment Variable    | Description                                                                                 |
|-------------------------|---------------------------------------------------------------------------------------------|
| CONSUL_AGENT            | Full address (host:port) of the Consul agent (e.g., `localhost:8500`).                      |
| SERVICE_NAME            | The name of the service in Consul used to retrieve database connection configuration.       |
| OTEL_COLLECTOR_GRPC     | Address of the OpenTelemetry Collector for exporting traces via gRPC.                       |
| OTP_ISSUER              | Issuer name used when generating OTP codes (used in 2FA systems).                           |
| JWT_ACCESS_TTL          | Lifetime duration of the access token (e.g., `15m` for 15 minutes).                         |
| JWT_REFRESH_TTL         | Lifetime duration of the refresh token (e.g., `360h` for 15 days).                          |
| JWT_ISSUER              | Issuer name for JWT tokens, typically the service or organization name.                     |
| POSTGRES_HOST           | Hostname or IP address of the PostgreSQL database server.                                   |
| POSTGRES_PORT           | Port number on which the PostgreSQL database server is listening.                           |
| POSTGRES_USER           | Username used to connect to the PostgreSQL database.                                        |
| POSTGRES_PASSWORD       | Password used to authenticate with the PostgreSQL database.                                 |
| POSTGRES_DB             | Name of the PostgreSQL database to connect to.                                              |
| REDIS_HOST              | Hostname or IP address of the Redis server.                                                 |
| REDIS_PORT              | Port number on which the Redis server is listening.                                         |
| REDIS_PASSWORD          | Password used to authenticate with the Redis server.                                        |
| REDIS_DB                | Redis database number to use (e.g., `0` is the default).                                    |
| ADMIN_ROLE_NAME         | Name of the admin role created during initial setup.                                        |
| ADMIN_EMAIL             | Email address of the initial admin user.                                                    |
| ADMIN_PASSWORD          | Password of the initial admin user.                                                         |

### 6. Run seed

```
task seed
```

## Run

```
task
```

### View Swagger docs

```
http://[SERVER_HOST]:[SERVER_PORT]/swagger/index.html
```

## Full list of commands

```
task -l
```
