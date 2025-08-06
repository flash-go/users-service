package dto

import (
	"time"
)

type AdminUserRoleResponse struct {
	Id      string    `json:"id"`
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
}
type AdminUserResponse struct {
	Id       uint                  `json:"id"`
	Created  time.Time             `json:"created"`
	Username string                `json:"username"`
	Email    string                `json:"email"`
	Name     string                `json:"name"`
	Role     AdminUserRoleResponse `json:"role"`
	Mfa      bool                  `json:"mfa"`
}
type UserAuth2faValidateResponse struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}
type UserAuth2faSettingsResponse struct {
	Secret string `json:"secret"`
	Url    string `json:"url"`
}
type UserAuthResponse struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Mfa     bool   `json:"mfa_required"`
}
type UserTokenValidateResponse struct {
	Id       string   `json:"id"`
	User     uint     `json:"user"`
	Role     string   `json:"role"`
	Mfa      bool     `json:"mfa"`
	Expires  int64    `json:"expires"`
	Issued   int64    `json:"issued"`
	Issuer   string   `json:"issuer"`
	Audience []string `json:"audience"`
}
