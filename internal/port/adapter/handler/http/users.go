package port

import (
	"github.com/flash-go/flash/http/server"
	"github.com/flash-go/sdk/errors"
)

type UsersHttpHandlerAdapterPort interface {
	// Roles
	AdminCreateRole(ctx server.ReqCtx)
	AdminGetRoles(ctx server.ReqCtx)
	AdminDeleteRole(ctx server.ReqCtx)
	AdminUpdateRole(ctx server.ReqCtx)
	// Users
	AdminCreateUser(ctx server.ReqCtx)
	AdminGetUsers(ctx server.ReqCtx)
	AdminDeleteUser(ctx server.ReqCtx)
	GetProfile(ctx server.ReqCtx)
	// Auth
	Auth2faValidate(ctx server.ReqCtx)
	Auth2faSettings(ctx server.ReqCtx)
	Auth2faEnable(ctx server.ReqCtx)
	Auth2faDisable(ctx server.ReqCtx)
	Auth(ctx server.ReqCtx)
	AuthTokenRenew(ctx server.ReqCtx)
	AuthTokenValidate(ctx server.ReqCtx)

	// Middlewares
	AuthMiddleware(twoFactor bool, roles ...string) func(server.ReqHandler) server.ReqHandler
}

var (
	ErrCreateUserRoleInvalidRequest      = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrUpdateUserRoleInvalidRequest      = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrCreateUserInvalidRequest          = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrDeleteUserInvalidRequest          = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrUserAuth2faValidateInvalidRequest = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrUserAuth2faSettingsInvalidRequest = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrUserAuth2faEnableInvalidRequest   = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrUserAuth2faDisableInvalidRequest  = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrUserAuthInvalidRequest            = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrUserTokenRenewInvalidRequest      = errors.New(errors.ErrBadRequest, "invalid_request")
	ErrUserTokenValidateInvalidRequest   = errors.New(errors.ErrBadRequest, "invalid_request")

	// Middleware
	ErrUserAuthInsufficientPermissions = errors.New(errors.ErrForbidden, "insufficient_permissions")
	ErrUserAuth2faRequired             = errors.New(errors.ErrUnauthorized, "2fa_required")
	ErrUserAuthInvalidToken            = errors.New(errors.ErrUnauthorized, "invalid_token")
)
