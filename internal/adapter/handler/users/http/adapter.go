package adapter

import (
	"slices"
	"strconv"

	"github.com/flash-go/sdk/errors"
	dto "github.com/flash-go/users-service/internal/dto/users"
	httpUsersHandlerAdapterPort "github.com/flash-go/users-service/internal/port/adapter/handler/users/http"
	usersServicePort "github.com/flash-go/users-service/internal/port/service/users"

	"github.com/flash-go/flash/http/server"
)

type Config struct {
	UsersService usersServicePort.Interface
}

func New(config *Config) httpUsersHandlerAdapterPort.Interface {
	return &adapter{
		config.UsersService,
	}
}

type adapter struct {
	usersService usersServicePort.Interface
}

// @Summary Create user role (admin)
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json,plain
// @Param request body dto.AdminCreateUserRoleRequest true "Create user role (admin)"
// @Success 201 {object} dto.AdminUserRoleResponse
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:invalid_role_id, bad_request:invalid_role_name, bad_request:role_exist_id, bad_request:role_exist_name"
// @Router /admin/users/roles [post]
func (a *adapter) AdminCreateRole(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.AdminCreateUserRoleRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Create data
	data := usersServicePort.CreateRoleData(request)

	// Create user role
	role, err := a.usersService.CreateRole(
		ctx.Context(),
		&data,
	)
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(201, dto.AdminUserRoleResponse(*role))
}

// @Summary Get user roles (admin)
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Success 200 {array} []dto.AdminUserRoleResponse
// @Router /admin/users/roles [get]
func (a *adapter) AdminGetRoles(ctx server.ReqCtx) {
	// Get user roles
	roles, err := a.usersService.GetRoles(ctx.Context())
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Build response
	response := make([]dto.AdminUserRoleResponse, len(*roles))
	for i, role := range *roles {
		response[i] = dto.AdminUserRoleResponse(role)
	}

	// Write success response
	ctx.WriteResponse(200, response)
}

// @Summary Delete user role (admin)
// @Tags roles
// @Security BearerAuth
// @Produce plain
// @Param id path string true "Role ID"
// @Success 200
// @Failure 400 {string} string "Possible error codes: bad_request:role_not_found, bad_request:role_is_used"
// @Router /admin/users/roles/{id} [delete]
func (a *adapter) AdminDeleteRole(ctx server.ReqCtx) {
	// Delete role
	if err := a.usersService.DeleteRole(
		ctx.Context(),
		ctx.UserValue("id").(string),
	); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, nil)
}

// @Summary Update user role (admin)
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce plain
// @Param id path string true "Role ID"
// @Param request body dto.AdminUpdateUserRoleRequest true "Update user role (admin)"
// @Success 200
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:role_not_found, bad_request:invalid_role_name, bad_request:role_exist_name"
// @Router /admin/users/roles/{id} [patch]
func (a *adapter) AdminUpdateRole(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.AdminUpdateUserRoleRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Create data
	data := usersServicePort.UpdateRoleData(request)

	// Update role
	if err := a.usersService.UpdateRole(
		ctx.Context(),
		ctx.UserValue("id").(string),
		&data,
	); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, nil)
}

// @Summary Create user (admin)
// @Tags users
// @Security BearerAuth
// @Accept json
// @Produce json,plain
// @Param request body dto.AdminCreateUserRequest true "Create user (admin)"
// @Success 201 {object} dto.AdminUserResponse
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:invalid_username, bad_request:invalid_email, bad_request:invalid_password, bad_request:user_exist_email, bad_request:user_exist_username, bad_request:role_not_found"
// @Router /admin/users [post]
func (a *adapter) AdminCreateUser(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.AdminCreateUserRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Create data
	data := usersServicePort.CreateUserData(request)

	// Create user
	user, err := a.usersService.CreateUser(
		ctx.Context(),
		&data,
	)
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(
		201,
		dto.AdminUserResponse{
			Id:       user.Id,
			Created:  user.Created,
			Username: user.Username,
			Email:    user.Email,
			Role:     dto.AdminUserRoleResponse(user.Role),
			Mfa:      user.Mfa,
		},
	)
}

// @Summary Get users (admin)
// @Tags users
// @Security BearerAuth
// @Produce json
// @Success 200 {array} []dto.AdminUserResponse
// @Router /admin/users [get]
func (a *adapter) AdminGetUsers(ctx server.ReqCtx) {
	// Get users
	users, err := a.usersService.GetUsers(ctx.Context())
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Build response
	response := make([]dto.AdminUserResponse, len(*users))
	for i, user := range *users {
		response[i] = dto.AdminUserResponse{
			Id:       user.Id,
			Created:  user.Created,
			Username: user.Username,
			Email:    user.Email,
			Role:     dto.AdminUserRoleResponse(user.Role),
			Mfa:      user.Mfa,
		}
	}

	// Write success response
	ctx.WriteResponse(200, response)
}

// @Summary Delete user (admin)
// @Tags users
// @Security BearerAuth
// @Produce plain
// @Param id path string true "User ID"
// @Success 200
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:user_not_found, bad_request:user_is_used"
// @Router /admin/users/{id} [delete]
func (a *adapter) AdminDeleteUser(ctx server.ReqCtx) {
	// Convert user id string to uint64
	id, err := strconv.ParseUint(ctx.UserValue("id").(string), 10, 64)
	if err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Delete user
	if err := a.usersService.DeleteUser(
		ctx.Context(),
		uint(id),
	); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, nil)
}

// @Summary User profile
// @Tags users
// @Security BearerAuth
// @Produce json
// @Success 200 {object} dto.AdminUserResponse
// @Router /users/profile [get]
func (a *adapter) GetProfile(ctx server.ReqCtx) {
	// Get profile
	user, err := a.usersService.GetUser(
		ctx.Context(),
		ctx.UserValue("user").(uint),
	)
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(
		200,
		dto.AdminUserResponse{
			Id:       user.Id,
			Created:  user.Created,
			Username: user.Username,
			Email:    user.Email,
			Role:     dto.AdminUserRoleResponse(user.Role),
			Mfa:      user.Mfa,
		},
	)
}

// @Summary User auth 2FA validate
// @Description Checking the two-factor authentication code
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json,plain
// @Param request body dto.UserAuth2faValidateRequest true "User auth 2FA validate"
// @Success 200 {object} dto.UserAuth2faValidateResponse
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:invalid_token, bad_request:mfa_disabled"
// @Router /users/auth/2fa/validate [post]
func (a *adapter) Auth2faValidate(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.UserAuth2faValidateRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Auth 2FA validate
	result, err := a.usersService.Auth2faValidate(
		ctx.Context(),
		&usersServicePort.UserAuth2faValidateData{
			User:  ctx.UserValue("user").(uint),
			Token: request.Token,
		},
	)
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, dto.UserAuth2faValidateResponse(*result))
}

// @Summary User auth 2FA settings
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json,plain
// @Param request body dto.UserAuth2faSettingsRequest true "User auth 2FA settings"
// @Success 200 {object} dto.UserAuth2faSettingsResponse
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:invalid_password"
// @Failure 401 {string} string "Possible error codes: unauthorized:invalid_credentials"
// @Router /users/auth/2fa/settings [post]
func (a *adapter) Auth2faSettings(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.UserAuth2faSettingsRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Auth 2FA settings
	result, err := a.usersService.Auth2faSettings(
		ctx.Context(),
		&usersServicePort.UserAuth2faSettingsData{
			User:     ctx.UserValue("user").(uint),
			Password: request.Password,
		},
	)
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, dto.UserAuth2faSettingsResponse(*result))
}

// @Summary User auth 2FA enable
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce plain
// @Param request body dto.UserAuth2faEnableRequest true "User auth 2FA enable"
// @Success 200
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:invalid_token, bad_request:ot_enabled"
// @Router /users/auth/2fa/enable [post]
func (a *adapter) Auth2faEnable(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.UserAuth2faEnableRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Auth 2FA enable
	if err := a.usersService.Auth2faEnable(
		ctx.Context(),
		&usersServicePort.UserAuth2faEnableData{
			User:  ctx.UserValue("user").(uint),
			Token: request.Token,
		},
	); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, nil)
}

// @Summary User auth 2FA disable
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce plain
// @Param request body dto.UserAuth2faDisableRequest true "User auth 2FA disable"
// @Success 200
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:invalid_password, bad_request:invalid_token, bad_request:mfa_disabled"
// @Failure 401 {string} string "Possible error codes: unauthorized:invalid_credentials"
// @Router /users/auth/2fa/disable [post]
func (a *adapter) Auth2faDisable(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.UserAuth2faDisableRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Auth 2FA disable
	if err := a.usersService.Auth2faDisable(
		ctx.Context(),
		&usersServicePort.UserAuth2faDisableData{
			User:     ctx.UserValue("user").(uint),
			Password: request.Password,
			Token:    request.Token,
		},
	); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, nil)
}

// @Summary User auth
// @Tags auth
// @Accept json
// @Produce json,plain
// @Param request body dto.UserAuthRequest true "User auth"
// @Success 200 {object} dto.UserAuthResponse
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:invalid_login, bad_request:invalid_password"
// @Failure 401 {string} string "Possible error codes: unauthorized:invalid_credentials"
// @Router /users/auth [post]
func (a *adapter) Auth(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.UserAuthRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Auth
	result, err := a.usersService.Auth(
		ctx.Context(),
		&usersServicePort.UserAuthData{
			Login:    request.Login,
			Password: request.Password,
		},
	)
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, dto.UserAuthResponse(*result))
}

// @Summary Renew JWT token
// @Tags auth
// @Accept json
// @Produce json,plain
// @Param request body dto.UserTokenRenewRequest true "Renew JWT token"
// @Success 200 {object} dto.UserAuthResponse
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:invalid_refresh_token, bad_request:invalid_token, bad_request:token_already_used"
// @Router /users/auth/token/renew [post]
func (a *adapter) AuthTokenRenew(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.UserTokenRenewRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Create data
	data := usersServicePort.UserAuthTokenRenewData(request)

	// Auth
	result, err := a.usersService.AuthTokenRenew(
		ctx.Context(),
		&data,
	)
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, dto.UserAuthResponse(*result))
}

// @Summary Validate JWT token
// @Description Parsing and validation of the access token. Mainly used in the authorization mechanism across various microservices.
// @Tags auth
// @Accept json
// @Produce json,plain
// @Param request body dto.UserTokenValidateRequest true "Validate JWT token"
// @Success 200 {object} dto.UserTokenValidateResponse
// @Failure 400 {string} string "Possible error codes: bad_request:invalid_request, bad_request:invalid_access_token"
// @Failure 401 {string} string "Possible error codes: unauthorized:invalid_token"
// @Router /users/auth/token/validate [post]
func (a *adapter) AuthTokenValidate(ctx server.ReqCtx) {
	// Parse request json body
	var request dto.UserTokenValidateRequest
	if err := ctx.ReadJson(&request); err != nil {
		ctx.WriteErrorResponse(errors.ErrBadRequest)
		return
	}

	// Validate request
	if err := request.Validate(); err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Create data
	data := usersServicePort.UserAuthTokenValidateData(request)

	// Validate access token
	result, err := a.usersService.AuthTokenValidate(
		ctx.Context(),
		&data,
	)
	if err != nil {
		ctx.WriteErrorResponse(err)
		return
	}

	// Write success response
	ctx.WriteResponse(200, dto.UserTokenValidateResponse(*result))
}

// Middlewares

func (a *adapter) AuthMiddleware(mfa bool, roles ...string) func(server.ReqHandler) server.ReqHandler {
	return func(handler server.ReqHandler) server.ReqHandler {
		return func(ctx server.ReqCtx) {
			// Get auth token
			token, err := ctx.GetBearerToken()
			if err != nil {
				ctx.WriteErrorResponse(httpUsersHandlerAdapterPort.ErrAuthInvalidToken)
				return
			}

			// Parse and validate access token
			user, err := a.usersService.AuthTokenValidate(
				ctx.Context(),
				&usersServicePort.UserAuthTokenValidateData{
					AccessToken: token,
				},
			)
			if err != nil {
				ctx.WriteErrorResponse(err)
				return
			}

			// Set data to ctx
			ctx.SetUserValue("user", user.User)
			ctx.SetUserValue("role", user.Role)
			ctx.SetUserValue("mfa", user.Mfa)

			// Check MFA
			if mfa && user.Mfa {
				ctx.WriteErrorResponse(httpUsersHandlerAdapterPort.ErrAuth2faRequired)
				return
			}

			// Check role permissions
			if len(roles) > 0 && !slices.Contains(roles, user.Role) {
				ctx.WriteErrorResponse(httpUsersHandlerAdapterPort.ErrAuthInsufficientPermissions)
				return
			}

			handler(ctx)
		}
	}
}
