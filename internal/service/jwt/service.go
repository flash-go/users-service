package service

import (
	"context"
	"fmt"
	"strconv"
	"time"

	jwtRepositoryAdapterPort "github.com/flash-go/users-service/internal/port/adapter/repository/jwt"
	jwtServicePort "github.com/flash-go/users-service/internal/port/service/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type jwtTokenClaims struct {
	Device string `json:"device"`
	Role   string `json:"role"`
	Mfa    bool   `json:"mfa"`
	jwt.RegisteredClaims
}

type Config struct {
	JwtRepository    jwtRepositoryAdapterPort.Interface
	JwtAccessExpire  string
	JwtRefreshExpire string
	JwtAccessKey     string
	JwtRefreshKey    string
	JwtIssuer        string
}

func New(config *Config) jwtServicePort.Interface {
	return &service{
		config.JwtRepository,
		config.JwtAccessExpire,
		config.JwtRefreshExpire,
		config.JwtAccessKey,
		config.JwtRefreshKey,
		config.JwtIssuer,
	}
}

type service struct {
	jwtRepository    jwtRepositoryAdapterPort.Interface
	jwtAccessExpire  string
	jwtRefreshExpire string
	jwtAccessKey     string
	jwtRefreshKey    string
	jwtIssuer        string
}

func (s *service) NewTokens(ctx context.Context, data jwtServicePort.NewJwtTokenData) (*jwtServicePort.JwtTokensResult, error) {
	// Generate JWT Access token
	access, err := s.NewAccessToken(ctx, data)
	if err != nil {
		return nil, err
	}

	// Generate JWT Refresh token
	refresh, err := s.NewRefreshToken(ctx, data)
	if err != nil {
		return nil, err
	}

	return &jwtServicePort.JwtTokensResult{
		Access:  *access,
		Refresh: *refresh,
	}, nil
}

func (s *service) NewAccessToken(ctx context.Context, data jwtServicePort.NewJwtTokenData) (*string, error) {
	token, _, err := s.newToken(data, s.jwtAccessKey, s.jwtAccessExpire)
	return token, err
}

func (s *service) NewRefreshToken(ctx context.Context, data jwtServicePort.NewJwtTokenData) (*string, error) {
	token, _, err := s.newToken(data, s.jwtRefreshKey, s.jwtRefreshExpire)
	return token, err
}

func (s *service) NewSession(ctx context.Context, user uint, device string, session jwtServicePort.Session) error {
	// Parse refresh token TTL
	ttl, err := time.ParseDuration(s.jwtRefreshExpire)
	if err != nil {
		return err
	}

	// New session
	if err := s.jwtRepository.NewSession(
		ctx,
		user,
		device,
		jwtRepositoryAdapterPort.Session(session),
		ttl,
	); err != nil {
		return err
	}

	return nil
}

func (s *service) GetSession(ctx context.Context, user uint, device string) (*jwtServicePort.Session, error) {
	// Get session
	repositorySession, err := s.jwtRepository.GetSession(ctx, user, device)
	if err != nil {
		return nil, err
	}
	if repositorySession == nil {
		return nil, nil
	}

	serviceSession := jwtServicePort.Session(*repositorySession)
	return &serviceSession, nil
}

func (s *service) UpdateSession(ctx context.Context, user uint, device, jti string) error {
	// Parse refresh token TTL
	ttl, err := time.ParseDuration(s.jwtRefreshExpire)
	if err != nil {
		return err
	}

	return s.jwtRepository.UpdateSession(ctx, user, device, jti, ttl)
}

func (s *service) DeleteSession(ctx context.Context, user uint, device string) error {
	return s.jwtRepository.DeleteSession(ctx, user, device)
}

func (s *service) GetActiveDevices(ctx context.Context, user uint) ([]jwtServicePort.Device, error) {
	// Get active devices
	repositoryDevices, err := s.jwtRepository.GetActiveDevices(ctx, user)
	if err != nil {
		return nil, err
	}

	// Map repository to service devices
	serviceDevices := make([]jwtServicePort.Device, 0, len(repositoryDevices))
	for _, device := range repositoryDevices {
		serviceDevices = append(
			serviceDevices,
			jwtServicePort.Device{
				Id:      device.Id,
				Session: jwtServicePort.Session(device.Session),
			},
		)
	}

	return serviceDevices, nil
}

func (s *service) ParseAccessToken(token string) (*jwtServicePort.ParseJwtTokenResult, error) {
	return s.parseToken(token, s.jwtAccessKey)
}

func (s *service) ParseRefreshToken(token string) (*jwtServicePort.ParseJwtTokenResult, error) {
	return s.parseToken(token, s.jwtRefreshKey)
}

func (s *service) newToken(data jwtServicePort.NewJwtTokenData, key, expire string) (*string, *jwtTokenClaims, error) {
	// Checking the minimum key length
	if err := s.checkKeyLen(key); err != nil {
		return nil, nil, err
	}

	// Parse duration
	dur, err := time.ParseDuration(expire)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid expiration duration: %v", err)
	}

	jti := uuid.NewString()
	now := time.Now()
	exp := now.Add(dur)

	// Create claims
	claims := &jwtTokenClaims{
		Device: data.Device,
		Role:   data.Role,
		Mfa:    data.Mfa,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   strconv.FormatUint(uint64(data.User), 10),
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.jwtIssuer,
			Audience:  []string{jwtServicePort.TokenAudience},
		},
	}

	// Create token
	token := jwt.NewWithClaims(signingMethod, claims)

	// Create signed token string
	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign token: %v", err)
	}

	return &tokenString, claims, nil
}

func (s *service) parseToken(token string, key string) (*jwtServicePort.ParseJwtTokenResult, error) {
	// Checking the minimum key length
	if err := s.checkKeyLen(key); err != nil {
		return nil, err
	}

	// Creating a parser with options
	parser := jwt.NewParser(
		// Manual security control that disallows the use of any algorithms other than HMAC.
		// You explicitly state that only HMAC (e.g., HS256, HS512) is accepted and everything
		// else is rejected. This check explicitly forbids any unsupported algorithms.
		jwt.WithValidMethods([]string{signingMethod.Alg()}),
		// In many distributed systems, clocks may differ slightly between services (for example,
		// the client and server might have a small time difference). To avoid issues caused by
		// this, we add a leeway (a time buffer).
		jwt.WithLeeway(5*time.Second),
		jwt.WithIssuer(s.jwtIssuer),
		jwt.WithAudience(jwtServicePort.TokenAudience),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)

	// Create token claims
	claims := &jwtTokenClaims{}

	// Parsing the token with custom claims
	t, err := parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		return []byte(key), nil
	})
	if err != nil || !t.Valid {
		return nil, jwtServicePort.ErrInvalidToken
	}

	// Parsing the Subject into a uint
	user, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing the subject into a uint failed: %v", err)
	}

	return &jwtServicePort.ParseJwtTokenResult{
		Id:       claims.ID,
		Device:   claims.Device,
		User:     uint(user),
		Role:     claims.Role,
		Mfa:      claims.Mfa,
		Expires:  claims.ExpiresAt.Unix(),
		Issued:   claims.IssuedAt.Unix(),
		Issuer:   claims.Issuer,
		Audience: claims.Audience,
	}, nil
}

func (s *service) checkKeyLen(key string) error {
	if len(key) < jwtServicePort.TokenKeyMinLen {
		return fmt.Errorf("signing key too short; must be at least %d characters", jwtServicePort.TokenKeyMinLen)
	}
	return nil
}
