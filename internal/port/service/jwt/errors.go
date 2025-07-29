package port

import "github.com/flash-go/sdk/errors"

var (
	ErrInvalidToken = errors.New(errors.ErrUnauthorized, "invalid_token")
)
