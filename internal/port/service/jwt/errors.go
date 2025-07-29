package port

import "github.com/flash-go/sdk/errors"

var (
	ErrInvalidToken = errors.New(errors.ErrBadRequest, "invalid_token")
)
