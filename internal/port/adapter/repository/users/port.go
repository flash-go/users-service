package port

import (
	"context"

	"github.com/flash-go/users-service/internal/domain/entity"
)

type Interface interface {
	// Roles
	CreateRole(ctx context.Context, role *entity.Role) error
	DeleteRoleById(ctx context.Context, id string) error
	UpdateRole(ctx context.Context, role *entity.Role) error
	UpdateRoleFieldsById(ctx context.Context, id string, fields *RoleFieldData) error
	FilterRoles(ctx context.Context, data *FilterRolesData) (*[]entity.Role, error)
	GetRoleBy(ctx context.Context, field RoleField, value any) (*entity.Role, error)
	ExistRoleBy(ctx context.Context, field RoleField, value any) (bool, error)
	// Users
	CreateUser(ctx context.Context, user *entity.User) error
	DeleteUserById(ctx context.Context, id uint) error
	UpdateUser(ctx context.Context, user *entity.User) error
	UpdateUserFieldsById(ctx context.Context, id uint, fields *UserFieldData) error
	FilterUsers(ctx context.Context, data *FilterUsersData) (*[]entity.User, error)
	GetUserBy(ctx context.Context, field UserField, value any) (*entity.User, error)
	GetUserByLogin(ctx context.Context, login string) (*entity.User, error)
	ExistUserBy(ctx context.Context, field UserField, value any) (bool, error)
}

type RoleField string

const (
	RoleFieldId   RoleField = "id"
	RoleFieldName RoleField = "name"
)

type RoleFieldData map[RoleField]any

type UserField string

const (
	UserFieldId        UserField = "id"
	UserFieldUsername  UserField = "username"
	UserFieldEmail     UserField = "email"
	UserFieldPassword  UserField = "password"
	UserFieldRoleId    UserField = "role_id"
	UserFieldMfa       UserField = "mfa"
	UserFieldOtpSecret UserField = "otp_secret"
)

type UserFieldData map[UserField]any

type FilterRolesData struct {
	Id   *[]string
	Name *[]string
}

type FilterUsersData struct {
	Id       *[]uint
	Username *[]string
	Email    *[]string
	Role     *[]string
}