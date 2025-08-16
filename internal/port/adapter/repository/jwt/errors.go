package port

import "github.com/flash-go/sdk/errors"

var (
	ErrSessionExpired = errors.New(errors.ErrBadRequest, "session_expired")
)
