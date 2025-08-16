package port

import (
	"github.com/flash-go/flash/http/server"
)

type Interface interface {
	// Roles
	AdminCreateRole(ctx server.ReqCtx)
	AdminFilterRoles(ctx server.ReqCtx)
	AdminDeleteRole(ctx server.ReqCtx)
	AdminUpdateRole(ctx server.ReqCtx)
	// Users
	AdminCreateUser(ctx server.ReqCtx)
	AdminFilterUsers(ctx server.ReqCtx)
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
	AuthLogout(ctx server.ReqCtx)
	AuthLogoutAll(ctx server.ReqCtx)
	AuthLogoutDevice(ctx server.ReqCtx)
	AuthDevices(ctx server.ReqCtx)
	// Middlewares
	AuthMiddleware(options ...AuthOption) func(server.ReqHandler) server.ReqHandler
}

type TokenValidateResult struct {
	Id       string
	Device   string
	User     uint
	Role     string
	Mfa      bool
	Expires  int64
	Issued   int64
	Issuer   string
	Audience []string
}

type AuthOption interface {
	Apply(server.ReqCtx, *TokenValidateResult) error
}
