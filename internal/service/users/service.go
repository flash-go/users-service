package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/flash-go/users-service/internal/domain/entity"
	"github.com/flash-go/users-service/internal/domain/factory"
	usersRepositoryAdapterPort "github.com/flash-go/users-service/internal/port/adapter/repository/users"
	jwtServicePort "github.com/flash-go/users-service/internal/port/service/jwt"
	otpServicePort "github.com/flash-go/users-service/internal/port/service/otp"
	usersServicePort "github.com/flash-go/users-service/internal/port/service/users"
)

type Config struct {
	UsersRepository usersRepositoryAdapterPort.Interface
	OtpService      otpServicePort.Interface
	JwtService      jwtServicePort.Interface
}

func New(config *Config) usersServicePort.Interface {
	return &service{
		config.UsersRepository,
		config.OtpService,
		config.JwtService,
	}
}

type service struct {
	usersRepository usersRepositoryAdapterPort.Interface
	otpService      otpServicePort.Interface
	jwtService      jwtServicePort.Interface
}

// Roles

func (s *service) CreateRole(ctx context.Context, data *usersServicePort.CreateRoleData) (*entity.Role, error) {
	// If id is found, return error
	if exists, err := s.usersRepository.ExistRoleBy(ctx, usersRepositoryAdapterPort.RoleFieldId, data.Id); err != nil {
		return nil, err
	} else if exists {
		return nil, usersServicePort.ErrRoleExistId
	}

	// If name is found, return error
	if exists, err := s.usersRepository.ExistRoleBy(ctx, usersRepositoryAdapterPort.RoleFieldName, data.Name); err != nil {
		return nil, err
	} else if exists {
		return nil, usersServicePort.ErrRoleExistName
	}

	// Create role entity
	role := factory.NewRole(
		factory.RoleData{
			Id:      data.Id,
			Name:    data.Name,
			Created: time.Now(),
		},
	)

	// Create role
	if err := s.usersRepository.CreateRole(ctx, role); err != nil {
		return nil, err
	}

	return role, nil
}

func (s *service) GetRoles(ctx context.Context) (*[]entity.Role, error) {
	return s.usersRepository.GetRoles(ctx)
}

func (s *service) DeleteRole(ctx context.Context, id string) error {
	return s.usersRepository.DeleteRoleById(ctx, id)
}

func (s *service) UpdateRole(ctx context.Context, id string, data *usersServicePort.UpdateRoleData) error {
	// Get role
	role, err := s.usersRepository.GetRoleBy(ctx, usersRepositoryAdapterPort.RoleFieldId, id)
	if err != nil {
		return err
	}

	if role.Name != data.Name {
		// If name is found, return error
		if exists, err := s.usersRepository.ExistRoleBy(ctx, usersRepositoryAdapterPort.RoleFieldName, data.Name); err != nil {
			return err
		} else if exists {
			return usersServicePort.ErrRoleExistName
		}
	}

	// Update role
	return s.usersRepository.UpdateRoleFieldsById(
		ctx,
		id,
		&usersRepositoryAdapterPort.RoleFieldData{
			usersRepositoryAdapterPort.RoleFieldName: data.Name,
		},
	)
}

// Users

func (s *service) CreateUser(ctx context.Context, data *usersServicePort.CreateUserData) (*entity.User, error) {
	// Set email and username to lower case
	email := strings.ToLower(data.Email)
	username := strings.ToLower(data.Username)

	// If email is found, return error
	if exists, err := s.usersRepository.ExistUserBy(ctx, usersRepositoryAdapterPort.UserFieldEmail, email); err != nil {
		return nil, err
	} else if exists {
		return nil, usersServicePort.ErrExistEmail
	}

	// If username is found, return error
	if exists, err := s.usersRepository.ExistUserBy(ctx, usersRepositoryAdapterPort.UserFieldUsername, username); err != nil {
		return nil, err
	} else if exists {
		return nil, usersServicePort.ErrExistUsername
	}

	// Get role
	role, err := s.usersRepository.GetRoleBy(ctx, usersRepositoryAdapterPort.RoleFieldId, data.Role)
	if err != nil {
		return nil, err
	}

	// Generate otp secret
	secret, err := s.otpService.GenerateSecret(ctx, email)
	if err != nil {
		return nil, err
	}

	// Create user entity
	user, err := factory.NewUser(
		factory.UserData{
			Username:  data.Username,
			Email:     data.Email,
			Password:  data.Password,
			Role:      *role,
			OtpSecret: *secret,
			Created:   time.Now(),
		},
	)
	if err != nil {
		return nil, err
	}

	// Create user
	if err := s.usersRepository.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *service) GetUsers(ctx context.Context) (*[]entity.User, error) {
	return s.usersRepository.GetUsers(ctx)
}

func (s *service) GetUser(ctx context.Context, id uint) (*entity.User, error) {
	return s.usersRepository.GetUserBy(ctx, usersRepositoryAdapterPort.UserFieldId, id)
}

func (s *service) DeleteUser(ctx context.Context, id uint) error {
	return s.usersRepository.DeleteUserById(ctx, id)
}

// Auth

func (s *service) Auth2faValidate(ctx context.Context, data *usersServicePort.UserAuth2faValidateData) (*usersServicePort.UserAuth2faValidateResult, error) {
	// Get user
	user, err := s.usersRepository.GetUserBy(ctx, usersRepositoryAdapterPort.UserFieldId, data.User)
	if err != nil {
		return nil, err
	}

	// Validate MFA
	if !user.Mfa {
		return nil, usersServicePort.ErrAuthMfaDisabled
	}

	// Validate token
	if err := s.otpService.ValidateToken(data.Token, user.OtpSecret); err != nil {
		return nil, err
	}

	// Create tokens
	tokens, err := s.jwtService.NewTokens(
		ctx,
		jwtServicePort.NewJwtTokenData{
			User: user.Id,
			Role: user.Role.Id,
			Mfa:  false,
		},
	)
	if err != nil {
		return nil, err
	}

	// Return tokens
	result := usersServicePort.UserAuth2faValidateResult(*tokens)
	return &result, nil
}

func (s *service) Auth2faSettings(ctx context.Context, data *usersServicePort.UserAuth2faSettingsData) (*usersServicePort.UserAuth2faSettingsResult, error) {
	// Get user
	user, err := s.usersRepository.GetUserBy(ctx, usersRepositoryAdapterPort.UserFieldId, data.User)
	if err != nil {
		return nil, err
	}

	// Validate password
	if err := user.ComparePassword(data.Password); err != nil {
		return nil, err
	}

	// Return data
	return &usersServicePort.UserAuth2faSettingsResult{
		Secret: user.OtpSecret,
		Url:    s.otpService.GenerateUrl(user.Email, user.OtpSecret),
	}, nil
}

func (s *service) Auth2faEnable(ctx context.Context, data *usersServicePort.UserAuth2faEnableData) error {
	// Get user
	user, err := s.usersRepository.GetUserBy(ctx, usersRepositoryAdapterPort.UserFieldId, data.User)
	if err != nil {
		return err
	}

	// Validate MFA
	if user.Mfa {
		return usersServicePort.ErrAuthMfaEnabled
	}

	// Validate token
	if err := s.otpService.ValidateToken(data.Token, user.OtpSecret); err != nil {
		return err
	}

	// Update MFA state
	return s.usersRepository.UpdateUserFieldsById(
		ctx,
		user.Id,
		&usersRepositoryAdapterPort.UserFieldData{
			usersRepositoryAdapterPort.UserFieldMfa: true,
		},
	)
}

func (s *service) Auth2faDisable(ctx context.Context, data *usersServicePort.UserAuth2faDisableData) error {
	// Get user
	user, err := s.usersRepository.GetUserBy(ctx, usersRepositoryAdapterPort.UserFieldId, data.User)
	if err != nil {
		return err
	}

	// Validate MFA
	if !user.Mfa {
		return usersServicePort.ErrAuthMfaDisabled
	}

	// Validate password
	if err := user.ComparePassword(data.Password); err != nil {
		return err
	}

	// Validate token
	if err := s.otpService.ValidateToken(data.Token, user.OtpSecret); err != nil {
		return err
	}

	// Update MFA state
	return s.usersRepository.UpdateUserFieldsById(
		ctx,
		user.Id,
		&usersRepositoryAdapterPort.UserFieldData{
			usersRepositoryAdapterPort.UserFieldMfa: false,
		},
	)
}

func (s *service) Auth(ctx context.Context, data *usersServicePort.UserAuthData) (*usersServicePort.UserAuthResult, error) {
	// To lower case
	login := strings.ToLower(data.Login)

	// Check login
	user, err := s.usersRepository.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, usersRepositoryAdapterPort.ErrUserNotFound) {
			return nil, entity.ErrUserInvalidCredentials
		}
		return nil, err
	}

	// Validate password
	if err := user.ComparePassword(data.Password); err != nil {
		return nil, err
	}

	// Create tokens
	tokens, err := s.jwtService.NewTokens(
		ctx,
		jwtServicePort.NewJwtTokenData{
			User: user.Id,
			Role: user.Role.Id,
			Mfa:  user.Mfa,
		},
	)
	if err != nil {
		return nil, err
	}

	// Return tokens and MFA flag
	return &usersServicePort.UserAuthResult{
		Access:  tokens.Access,
		Refresh: tokens.Refresh,
		Mfa:     user.Mfa,
	}, nil
}

func (s *service) AuthTokenRenew(ctx context.Context, data *usersServicePort.UserAuthTokenRenewData) (*usersServicePort.UserAuthResult, error) {
	// Parse refresh token
	token, err := s.jwtService.ParseRefreshToken(data.RefreshToken)
	if err != nil {
		return nil, err
	}

	// Get refresh token JTI by user id
	jti, err := s.jwtService.GetRefreshTokenJtiFromCache(ctx, token.User)
	if err != nil {
		return nil, err
	}

	// Check already used token
	if *jti != token.Id {
		return nil, usersServicePort.ErrAuthRefreshTokenAlreadyUsed
	}

	// Get user data
	user, err := s.usersRepository.GetUserBy(ctx, usersRepositoryAdapterPort.UserFieldId, token.User)
	if err != nil {
		return nil, err
	}

	// Create tokens
	tokens, err := s.jwtService.NewTokens(
		ctx,
		jwtServicePort.NewJwtTokenData{
			User: user.Id,
			Role: user.Role.Id,
			Mfa:  token.Mfa,
		},
	)
	if err != nil {
		return nil, err
	}

	// Return tokens and MFA flag
	return &usersServicePort.UserAuthResult{
		Access:  tokens.Access,
		Refresh: tokens.Refresh,
		Mfa:     token.Mfa,
	}, nil
}

func (s *service) AuthTokenValidate(ctx context.Context, data *usersServicePort.UserAuthTokenValidateData) (*usersServicePort.UserAuthTokenValidateResult, error) {
	// Parse and validate access token
	t, err := s.jwtService.ParseAccessToken(data.AccessToken)
	if err != nil {
		return nil, err
	}

	result := usersServicePort.UserAuthTokenValidateResult(*t)
	return &result, nil
}
