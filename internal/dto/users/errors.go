package dto

import (
	"github.com/flash-go/sdk/errors"
)

var (
	ErrUserRoleInvalidId           = errors.New(errors.ErrBadRequest, "invalid_role_id")
	ErrUserRoleInvalidName         = errors.New(errors.ErrBadRequest, "invalid_role_name")
	ErrUserInvalidUsername         = errors.New(errors.ErrBadRequest, "invalid_username")
	ErrUserInvalidEmail            = errors.New(errors.ErrBadRequest, "invalid_email")
	ErrUserInvalidPassword         = errors.New(errors.ErrBadRequest, "invalid_password")
	ErrUserInvalidLogin            = errors.New(errors.ErrBadRequest, "invalid_login")
	ErrUserAuth2faInvalidToken     = errors.New(errors.ErrBadRequest, "invalid_token")
	ErrUserAuth2faInvalidPassword  = errors.New(errors.ErrBadRequest, "invalid_password")
	ErrUserAuthInvalidAccessToken  = errors.New(errors.ErrBadRequest, "invalid_access_token")
	ErrUserAuthInvalidRefreshToken = errors.New(errors.ErrBadRequest, "invalid_refresh_token")
)
