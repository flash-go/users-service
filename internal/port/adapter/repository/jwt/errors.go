package port

import "github.com/flash-go/sdk/errors"

var (
	ErrRefreshTokenExpired = errors.New(errors.ErrBadRequest, "refresh_token_expired")
)
