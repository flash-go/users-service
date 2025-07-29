package port

import "github.com/flash-go/sdk/errors"

var (
	ErrAuthInsufficientPermissions = errors.New(errors.ErrForbidden, "insufficient_permissions")
	ErrAuth2faRequired             = errors.New(errors.ErrUnauthorized, "2fa_required")
	ErrAuthInvalidToken            = errors.New(errors.ErrUnauthorized, "invalid_token")
)
