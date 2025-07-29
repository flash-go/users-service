package port

import "github.com/flash-go/sdk/errors"

var (
	ErrUserRoleNotFound     = errors.New(errors.ErrBadRequest, "role_not_found")
	ErrUserNotFound         = errors.New(errors.ErrBadRequest, "user_not_found")
	ErrDeleteUserRoleIsUsed = errors.New(errors.ErrBadRequest, "role_is_used")
	ErrDeleteUserIsUsed     = errors.New(errors.ErrBadRequest, "user_is_used")
)
