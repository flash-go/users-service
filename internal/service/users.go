package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/flash-go/users-service/internal/domain/entity"
	"github.com/flash-go/users-service/internal/domain/factory"
	repositoryAdapterPort "github.com/flash-go/users-service/internal/port/adapter/repository"
	servicePort "github.com/flash-go/users-service/internal/port/service"
)

type UsersServiceConfig struct {
	UsersRepository repositoryAdapterPort.UsersRepositoryAdapterPort
	OtpService      servicePort.OtpServicePort
	JwtService      servicePort.JwtServicePort
}

func NewUsersService(config *UsersServiceConfig) servicePort.UsersServicePort {
	return &usersService{
		config.UsersRepository,
		config.OtpService,
		config.JwtService,
	}
}

type usersService struct {
	usersRepository repositoryAdapterPort.UsersRepositoryAdapterPort
	otpService      servicePort.OtpServicePort
	jwtService      servicePort.JwtServicePort
}

// Roles

func (s *usersService) CreateRole(ctx context.Context, data *servicePort.CreateRoleData) (*entity.Role, error) {
	// If id is found, return error
	if exists, err := s.usersRepository.ExistRoleBy(ctx, repositoryAdapterPort.RoleFieldId, data.Id); err != nil {
		return nil, err
	} else if exists {
		return nil, servicePort.ErrUserRoleExistId
	}

	// If name is found, return error
	if exists, err := s.usersRepository.ExistRoleBy(ctx, repositoryAdapterPort.RoleFieldName, data.Name); err != nil {
		return nil, err
	} else if exists {
		return nil, servicePort.ErrUserRoleExistName
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

func (s *usersService) GetRoles(ctx context.Context) (*[]entity.Role, error) {
	return s.usersRepository.GetRoles(ctx)
}

func (s *usersService) DeleteRole(ctx context.Context, id string) error {
	return s.usersRepository.DeleteRoleById(ctx, id)
}

func (s *usersService) UpdateRole(ctx context.Context, id string, data *servicePort.UpdateRoleData) error {
	// Get role
	role, err := s.usersRepository.GetRoleBy(ctx, repositoryAdapterPort.RoleFieldId, id)
	if err != nil {
		return err
	}

	if role.Name != data.Name {
		// If name is found, return error
		if exists, err := s.usersRepository.ExistRoleBy(ctx, repositoryAdapterPort.RoleFieldName, data.Name); err != nil {
			return err
		} else if exists {
			return servicePort.ErrUserRoleExistName
		}
	}

	// Update role
	return s.usersRepository.UpdateRoleFieldsById(
		ctx,
		id,
		&repositoryAdapterPort.RoleFieldData{
			repositoryAdapterPort.RoleFieldName: data.Name,
		},
	)
}

// Users

func (s *usersService) CreateUser(ctx context.Context, data *servicePort.CreateUserData) (*entity.User, error) {
	// Set email and username to lower case
	email := strings.ToLower(data.Email)
	username := strings.ToLower(data.Username)

	// If email is found, return error
	if exists, err := s.usersRepository.ExistUserBy(ctx, repositoryAdapterPort.UserFieldEmail, email); err != nil {
		return nil, err
	} else if exists {
		return nil, servicePort.ErrUserExistEmail
	}

	// If username is found, return error
	if exists, err := s.usersRepository.ExistUserBy(ctx, repositoryAdapterPort.UserFieldUsername, username); err != nil {
		return nil, err
	} else if exists {
		return nil, servicePort.ErrUserExistUsername
	}

	// Get role
	role, err := s.usersRepository.GetRoleBy(ctx, repositoryAdapterPort.RoleFieldId, data.Role)
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

func (s *usersService) GetUsers(ctx context.Context) (*[]entity.User, error) {
	return s.usersRepository.GetUsers(ctx)
}

func (s *usersService) GetUser(ctx context.Context, id uint) (*entity.User, error) {
	return s.usersRepository.GetUserBy(ctx, repositoryAdapterPort.UserFieldId, id)
}

func (s *usersService) DeleteUser(ctx context.Context, id uint) error {
	return s.usersRepository.DeleteUserById(ctx, id)
}

// Auth

func (s *usersService) Auth2faValidate(ctx context.Context, data *servicePort.UserAuth2faValidateData) (*servicePort.UserAuth2faValidateResult, error) {
	// Get user
	user, err := s.usersRepository.GetUserBy(ctx, repositoryAdapterPort.UserFieldId, data.User)
	if err != nil {
		return nil, err
	}

	// Validate MFA
	if !user.Mfa {
		return nil, servicePort.ErrUserAuthMfaDisabled
	}

	// Validate token
	if err := s.otpService.ValidateToken(data.Token, user.OtpSecret); err != nil {
		return nil, err
	}

	// Create tokens
	tokens, err := s.jwtService.NewTokens(
		ctx,
		servicePort.NewJwtTokenData{
			User: user.Id,
			Role: user.Role.Id,
			Mfa:  false,
		},
	)
	if err != nil {
		return nil, err
	}

	// Return tokens
	result := servicePort.UserAuth2faValidateResult(*tokens)
	return &result, nil
}

func (s *usersService) Auth2faSettings(ctx context.Context, data *servicePort.UserAuth2faSettingsData) (*servicePort.UserAuth2faSettingsResult, error) {
	// Get user
	user, err := s.usersRepository.GetUserBy(ctx, repositoryAdapterPort.UserFieldId, data.User)
	if err != nil {
		return nil, err
	}

	// Validate password
	if err := user.ComparePassword(data.Password); err != nil {
		return nil, err
	}

	// Return data
	return &servicePort.UserAuth2faSettingsResult{
		Secret: user.OtpSecret,
		Url:    s.otpService.GenerateUrl(user.Email, user.OtpSecret),
	}, nil
}

func (s *usersService) Auth2faEnable(ctx context.Context, data *servicePort.UserAuth2faEnableData) error {
	// Get user
	user, err := s.usersRepository.GetUserBy(ctx, repositoryAdapterPort.UserFieldId, data.User)
	if err != nil {
		return err
	}

	// Validate MFA
	if user.Mfa {
		return servicePort.ErrUserAuthMfaEnabled
	}

	// Validate token
	if err := s.otpService.ValidateToken(data.Token, user.OtpSecret); err != nil {
		return err
	}

	// Update MFA state
	return s.usersRepository.UpdateUserFieldsById(
		ctx,
		user.Id,
		&repositoryAdapterPort.UserFieldData{
			repositoryAdapterPort.UserFieldMfa: true,
		},
	)
}

func (s *usersService) Auth2faDisable(ctx context.Context, data *servicePort.UserAuth2faDisableData) error {
	// Get user
	user, err := s.usersRepository.GetUserBy(ctx, repositoryAdapterPort.UserFieldId, data.User)
	if err != nil {
		return err
	}

	// Validate MFA
	if !user.Mfa {
		return servicePort.ErrUserAuthMfaDisabled
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
		&repositoryAdapterPort.UserFieldData{
			repositoryAdapterPort.UserFieldMfa: false,
		},
	)
}

func (s *usersService) Auth(ctx context.Context, data *servicePort.UserAuthData) (*servicePort.UserAuthResult, error) {
	// To lower case
	login := strings.ToLower(data.Login)

	// Check login
	user, err := s.usersRepository.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, repositoryAdapterPort.ErrUserNotFound) {
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
		servicePort.NewJwtTokenData{
			User: user.Id,
			Role: user.Role.Id,
			Mfa:  user.Mfa,
		},
	)
	if err != nil {
		return nil, err
	}

	// Return tokens and MFA flag
	return &servicePort.UserAuthResult{
		Access:  tokens.Access,
		Refresh: tokens.Refresh,
		Mfa:     user.Mfa,
	}, nil
}

func (s *usersService) AuthTokenRenew(ctx context.Context, data *servicePort.UserAuthTokenRenewData) (*servicePort.UserAuthResult, error) {
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
		return nil, servicePort.ErrUserAuthRefreshTokenAlreadyUsed
	}

	// Get user data
	user, err := s.usersRepository.GetUserBy(ctx, repositoryAdapterPort.UserFieldId, token.User)
	if err != nil {
		return nil, err
	}

	// Create tokens
	tokens, err := s.jwtService.NewTokens(
		ctx,
		servicePort.NewJwtTokenData{
			User: user.Id,
			Role: user.Role.Id,
			Mfa:  token.Mfa,
		},
	)
	if err != nil {
		return nil, err
	}

	// Return tokens and MFA flag
	return &servicePort.UserAuthResult{
		Access:  tokens.Access,
		Refresh: tokens.Refresh,
		Mfa:     token.Mfa,
	}, nil
}

func (s *usersService) AuthTokenValidate(ctx context.Context, data *servicePort.UserAuthTokenValidateData) (*servicePort.UserAuthTokenValidateResult, error) {
	// Parse and validate access token
	t, err := s.jwtService.ParseAccessToken(data.AccessToken)
	if err != nil {
		return nil, err
	}

	result := servicePort.UserAuthTokenValidateResult(*t)
	return &result, nil
}
