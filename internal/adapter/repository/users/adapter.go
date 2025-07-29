package adapter

import (
	"context"
	"errors"
	"fmt"
	"net/mail"

	"github.com/flash-go/users-service/internal/adapter/repository/users/model"
	"github.com/flash-go/users-service/internal/domain/entity"
	usersRepositoryAdapterPort "github.com/flash-go/users-service/internal/port/adapter/repository/users"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

type Config struct {
	PostgresClient *gorm.DB
}

func New(config *Config) usersRepositoryAdapterPort.Interface {
	return &adapter{
		postgres: config.PostgresClient,
	}
}

type adapter struct {
	postgres *gorm.DB
}

// Roles

func (a *adapter) CreateRole(ctx context.Context, role *entity.Role) error {
	// Mapping entity to model
	obj := model.UserRole(*role)

	// Save role to database
	if err := a.postgres.WithContext(ctx).Create(&obj).Error; err != nil {
		return err
	}

	// Mapping model to entity
	*role = entity.Role(obj)

	return nil
}

func (a *adapter) DeleteRoleById(ctx context.Context, id string) error {
	// Delete role from database
	result := a.postgres.WithContext(ctx).Delete(&model.UserRole{}, "id = ?", id)

	// Check errors
	if result.Error != nil {
		if pgErr, ok := result.Error.(*pgconn.PgError); ok {
			switch pgErr.Code {
			case "23503":
				return usersRepositoryAdapterPort.ErrDeleteUserRoleIsUsed
			}
		}
		return result.Error
	}

	// If role not found
	if result.RowsAffected == 0 {
		return usersRepositoryAdapterPort.ErrUserRoleNotFound
	}

	return nil
}

func (a *adapter) UpdateRole(ctx context.Context, role *entity.Role) error {
	// Mapping entity to model
	obj := model.UserRole(*role)

	// Update role in database
	result := a.postgres.WithContext(ctx).Model(&obj).Where("id = ?", obj.Id).Updates(&obj)

	// Check errors
	if result.Error != nil {
		return result.Error
	}

	// If role not found
	if result.RowsAffected == 0 {
		return usersRepositoryAdapterPort.ErrUserRoleNotFound
	}

	return nil
}

func (a *adapter) UpdateRoleFieldsById(ctx context.Context, id string, fields *usersRepositoryAdapterPort.RoleFieldData) error {
	// Update role in database
	result := a.postgres.WithContext(ctx).Model(&model.UserRole{}).Where("id = ?", id).Updates(mapUpdatedFields(fields))

	// Check errors
	if result.Error != nil {
		return result.Error
	}

	// If role not found
	if result.RowsAffected == 0 {
		return usersRepositoryAdapterPort.ErrUserRoleNotFound
	}

	return nil
}

func (a *adapter) GetRoles(ctx context.Context) (*[]entity.Role, error) {
	// Get roles from database
	obj := []model.UserRole{}
	if err := a.postgres.WithContext(ctx).Find(&obj).Error; err != nil {
		return nil, err
	}

	// Mapping model to entity
	roles := make([]entity.Role, len(obj))
	for i, item := range obj {
		roles[i] = entity.Role(item)
	}

	return &roles, nil
}

func (a *adapter) GetRoleBy(ctx context.Context, field usersRepositoryAdapterPort.RoleField, value any) (*entity.Role, error) {
	// Get role from database
	obj := model.UserRole{}
	err := a.postgres.WithContext(ctx).Where(fmt.Sprintf("%s = ?", string(field)), value).First(&obj).Error

	// Check error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, usersRepositoryAdapterPort.ErrUserRoleNotFound
	}
	if err != nil {
		return nil, err
	}

	// Mapping model to entity
	role := entity.Role(obj)

	return &role, nil
}

func (a *adapter) ExistRoleBy(ctx context.Context, field usersRepositoryAdapterPort.RoleField, value any) (bool, error) {
	var count int64

	err := a.postgres.
		WithContext(ctx).
		Model(&model.UserRole{}).
		Where(fmt.Sprintf("%s = ?", string(field)), value).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// Users

func (a *adapter) CreateUser(ctx context.Context, user *entity.User) error {
	// Mapping entity to model
	obj := modelUserFromEntity(user)

	// Save user to database
	if err := a.postgres.WithContext(ctx).Create(obj).Error; err != nil {
		return err
	}

	// Preload role
	if err := a.postgres.Preload("Role").First(obj, obj.Id).Error; err != nil {
		return err
	}

	// Mapping model to entity
	*user = *entityUserFromModel(obj)

	return nil
}

func (a *adapter) DeleteUserById(ctx context.Context, id uint) error {
	// Delete user from database
	result := a.postgres.WithContext(ctx).Delete(&model.User{}, "id = ?", id)

	// Check errors
	if result.Error != nil {
		if pgErr, ok := result.Error.(*pgconn.PgError); ok {
			switch pgErr.Code {
			case "23503":
				return usersRepositoryAdapterPort.ErrDeleteUserIsUsed
			}
		}
		return result.Error
	}

	// If user not found
	if result.RowsAffected == 0 {
		return usersRepositoryAdapterPort.ErrUserNotFound
	}

	return nil
}

func (a *adapter) UpdateUser(ctx context.Context, user *entity.User) error {
	// Mapping entity to model
	obj := modelUserFromEntity(user)

	// Update user in database
	result := a.postgres.WithContext(ctx).Model(&obj).Where("id = ?", obj.Id).Updates(&obj)

	// Check errors
	if result.Error != nil {
		return result.Error
	}

	// If user not found
	if result.RowsAffected == 0 {
		return usersRepositoryAdapterPort.ErrUserNotFound
	}

	return nil
}

func (a *adapter) UpdateUserFieldsById(ctx context.Context, id uint, fields *usersRepositoryAdapterPort.UserFieldData) error {
	// Update user in database
	result := a.postgres.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Updates(mapUpdatedFields(fields))

	// Check errors
	if result.Error != nil {
		return result.Error
	}

	// If user not found
	if result.RowsAffected == 0 {
		return usersRepositoryAdapterPort.ErrUserNotFound
	}

	return nil
}

func (a *adapter) GetUsers(ctx context.Context) (*[]entity.User, error) {
	// Get users from database
	obj := []model.User{}
	if err := a.postgres.WithContext(ctx).Preload("Role").Find(&obj).Error; err != nil {
		return nil, err
	}

	// Mapping model to entity
	users := make([]entity.User, len(obj))
	for i, item := range obj {
		users[i] = *entityUserFromModel(&item)
	}

	return &users, nil
}

func (a *adapter) GetUserByLogin(ctx context.Context, login string) (*entity.User, error) {
	if _, err := mail.ParseAddress(login); err == nil {
		return a.GetUserBy(ctx, "email", login)
	}
	return a.GetUserBy(ctx, "username", login)
}

func (a *adapter) GetUserBy(ctx context.Context, field usersRepositoryAdapterPort.UserField, value any) (*entity.User, error) {
	// Get user from database
	obj := &model.User{}
	err := a.postgres.WithContext(ctx).Preload("Role").Where(fmt.Sprintf("%s = ?", string(field)), value).First(obj).Error

	// Check error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, usersRepositoryAdapterPort.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	// Mapping model to entity
	return entityUserFromModel(obj), nil
}

func (a *adapter) ExistUserBy(ctx context.Context, field usersRepositoryAdapterPort.UserField, value any) (bool, error) {
	var count int64
	err := a.postgres.
		WithContext(ctx).
		Model(&model.User{}).
		Where(fmt.Sprintf("%s = ?", string(field)), value).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func modelUserFromEntity(u *entity.User) *model.User {
	return &model.User{
		Id:        u.Id,
		Created:   u.Created,
		Username:  u.Username,
		Email:     u.Email,
		Password:  u.Password,
		RoleId:    u.Role.Id,
		Mfa:       u.Mfa,
		OtpSecret: u.OtpSecret,
	}
}

func entityUserFromModel(m *model.User) *entity.User {
	return &entity.User{
		Id:        m.Id,
		Created:   m.Created,
		Username:  m.Username,
		Email:     m.Email,
		Password:  m.Password,
		Role:      entity.Role(m.Role),
		Mfa:       m.Mfa,
		OtpSecret: m.OtpSecret,
	}
}

func mapUpdatedFields[K ~string, M ~map[K]any](data *M) map[string]any {
	u := make(map[string]any, len(*data))
	for k, v := range *data {
		u[string(k)] = v
	}
	return u
}
