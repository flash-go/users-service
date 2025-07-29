package port

import "github.com/flash-go/sdk/errors"

var (
	ErrRoleNotFound  = errors.New(errors.ErrBadRequest, "role_not_found")
	ErrRoleExistId   = errors.New(errors.ErrBadRequest, "role_exist_id")
	ErrRoleExistName = errors.New(errors.ErrBadRequest, "role_exist_name")

	ErrExistEmail    = errors.New(errors.ErrBadRequest, "user_exist_email")
	ErrExistUsername = errors.New(errors.ErrBadRequest, "user_exist_username")

	ErrAuthMfaDisabled = errors.New(errors.ErrBadRequest, "mfa_disabled")
	ErrAuthMfaEnabled  = errors.New(errors.ErrBadRequest, "mfa_enabled")

	ErrAuthRefreshTokenAlreadyUsed = errors.New(errors.ErrBadRequest, "token_already_used")
)
