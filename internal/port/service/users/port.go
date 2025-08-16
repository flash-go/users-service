package port

import (
	"context"

	"github.com/flash-go/users-service/internal/domain/entity"
)

type Interface interface {
	// Roles
	CreateRole(ctx context.Context, data *CreateRoleData) (*entity.Role, error)
	FilterRoles(ctx context.Context, data *FilterRolesData) (*[]entity.Role, error)
	DeleteRole(ctx context.Context, id string) error
	UpdateRole(ctx context.Context, id string, data *UpdateRoleData) error
	// Users
	CreateUser(ctx context.Context, data *CreateUserData) (*entity.User, error)
	FilterUsers(ctx context.Context, data *FilterUsersData) (*[]entity.User, error)
	GetUser(ctx context.Context, id uint) (*entity.User, error)
	DeleteUser(ctx context.Context, id uint) error
	// Auth
	Auth2faValidate(ctx context.Context, data *UserAuth2faValidateData) (*UserAuth2faValidateResult, error)
	Auth2faSettings(ctx context.Context, data *UserAuth2faSettingsData) (*UserAuth2faSettingsResult, error)
	Auth2faEnable(ctx context.Context, data *UserAuth2faEnableData) error
	Auth2faDisable(ctx context.Context, data *UserAuth2faDisableData) error
	Auth(ctx context.Context, data *UserAuthData) (*UserAuthResult, error)
	TokenRenew(ctx context.Context, data *UserAuthTokenRenewData) (*UserAuthResult, error)
	TokenValidate(ctx context.Context, data *UserAuthTokenValidateData) (*UserAuthTokenValidateResult, error)
	LogoutDevice(ctx context.Context, data *UserAuthLogoutDeviceData) error
	LogoutAll(ctx context.Context, data *UserAuthLogoutAllData) error
	GetActiveDevices(ctx context.Context, user uint) ([]Device, error)
}

// Args

type CreateRoleData struct {
	Id   string
	Name string
}
type FilterRolesData struct {
	Id   *[]string
	Name *[]string
}
type UpdateRoleData struct {
	Name string
}
type CreateUserData struct {
	Username string
	Email    string
	Password string
	Name     string
	Role     string
}
type FilterUsersData struct {
	Id       *[]uint
	Username *[]string
	Email    *[]string
	Role     *[]string
}
type UserAuth2faValidateData struct {
	User  uint
	Token string
}
type UserAuth2faSettingsData struct {
	User     uint
	Password string
}
type UserAuth2faEnableData struct {
	User  uint
	Token string
}
type UserAuth2faDisableData struct {
	User     uint
	Password string
	Token    string
}
type UserAuthData struct {
	Login    string
	Password string
	Meta     UserAuthMetaData
}
type UserAuthMetaData struct {
	Location       string
	Ip             string
	UserAgent      string
	OsFullName     string
	OsName         string
	OsVersion      string
	Platform       string
	Model          string
	BrowserName    string
	BrowserVersion string
	EngineName     string
	EngineVersion  string
}
type UserAuthTokenRenewData struct {
	RefreshToken string
}
type UserAuthTokenValidateData struct {
	AccessToken string
}
type UserAuthLogoutDeviceData struct {
	User   uint
	Device string
}
type UserAuthLogoutAllData struct {
	User uint
}

// Results

type UserAuth2faValidateResult struct {
	Access  string
	Refresh string
}
type UserAuth2faSettingsResult struct {
	Secret string
	Url    string
}
type UserAuthResult struct {
	Access  string
	Refresh string
	Mfa     bool
}
type UserAuthTokenValidateResult struct {
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
type Session struct {
	IssuedAt       string
	Location       string
	Ip             string
	UserAgent      string
	OsFullName     string
	OsName         string
	OsVersion      string
	Platform       string
	Model          string
	BrowserName    string
	BrowserVersion string
	EngineName     string
	EngineVersion  string
}
type Device struct {
	Id      string
	Session Session
}
