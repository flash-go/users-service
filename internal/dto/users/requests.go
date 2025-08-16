package dto

import (
	"net/mail"
	"regexp"
	"unicode"
)

const (
	usernameRegexp = `^[a-zA-Z0-9-]{3,15}$`
	minPasswordLen = 7
)

type AdminCreateUserRoleRequest struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

func (r *AdminCreateUserRoleRequest) Validate() error {
	if r.Id == "" {
		return ErrUserRoleInvalidId
	}
	if r.Name == "" {
		return ErrUserRoleInvalidName
	}
	return nil
}

type AdminUpdateUserRoleRequest struct {
	Name string `json:"name"`
}

func (r *AdminUpdateUserRoleRequest) Validate() error {
	if r.Name == "" {
		return ErrUserRoleInvalidName
	}
	return nil
}

type AdminFilterRolesRequest struct {
	Id   *[]string `json:"id"`
	Name *[]string `json:"name"`
}

type AdminCreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

func (r *AdminCreateUserRequest) Validate() error {
	if err := r.ValidateName(); err != nil {
		return err
	}
	if err := r.ValidateUsername(); err != nil {
		return err
	}
	if err := r.ValidateEmail(); err != nil {
		return err
	}
	if err := r.ValidatePassword(); err != nil {
		return err
	}
	return nil
}

func (r *AdminCreateUserRequest) ValidateName() error {
	if r.Name == "" {
		return ErrUserInvalidName
	}
	return nil
}

func (r *AdminCreateUserRequest) ValidateUsername() error {
	if !regexp.MustCompile(usernameRegexp).MatchString(r.Username) {
		return ErrUserInvalidUsername
	}
	return nil
}

func (r *AdminCreateUserRequest) ValidateEmail() error {
	if _, err := mail.ParseAddress(r.Email); err != nil {
		return ErrUserInvalidEmail
	}
	return nil
}

func (r *AdminCreateUserRequest) ValidatePassword() error {
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	if len(r.Password) >= minPasswordLen {
		hasMinLen = true
	}
	for _, char := range r.Password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	if !hasMinLen || !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return ErrUserInvalidPassword
	}
	return nil
}

type AdminFilterUsersRequest struct {
	Id       *[]uint   `json:"id"`
	Username *[]string `json:"username"`
	Email    *[]string `json:"email"`
	Role     *[]string `json:"role"`
}

type UserAuth2faValidateRequest struct {
	Token string `json:"token"`
}

func (r *UserAuth2faValidateRequest) Validate() error {
	if r.Token == "" {
		return ErrUserAuth2faInvalidToken
	}
	return nil
}

type UserAuth2faSettingsRequest struct {
	Password string `json:"password"`
}

func (r *UserAuth2faSettingsRequest) Validate() error {
	if r.Password == "" {
		return ErrUserAuth2faInvalidPassword
	}
	return nil
}

type UserAuth2faEnableRequest struct {
	Token string `json:"token"`
}

func (r *UserAuth2faEnableRequest) Validate() error {
	if r.Token == "" {
		return ErrUserAuth2faInvalidToken
	}
	return nil
}

type UserAuth2faDisableRequest struct {
	Password string `json:"password"`
	Token    string `json:"token"`
}

func (r *UserAuth2faDisableRequest) Validate() error {
	if r.Password == "" {
		return ErrUserAuth2faInvalidPassword
	}
	if r.Token == "" {
		return ErrUserAuth2faInvalidToken
	}
	return nil
}

type UserAuthRequest struct {
	Login    string                   `json:"login"`
	Password string                   `json:"password"`
	Metadata *UserAuthMetadataRequest `json:"metadata"`
}

type UserAuthMetadataRequest struct {
	Location       string `json:"location"`
	Ip             string `json:"ip"`
	UserAgent      string `json:"user_agent"`
	OsFullName     string `json:"os_full_name"`
	OsName         string `json:"os_name"`
	OsVersion      string `json:"os_version"`
	Platform       string `json:"platform"`
	Model          string `json:"model"`
	BrowserName    string `json:"browser_name"`
	BrowserVersion string `json:"browser_version"`
	EngineName     string `json:"engine_name"`
	EngineVersion  string `json:"engine_version"`
}

func (r *UserAuthRequest) Validate() error {
	if r.Login == "" {
		return ErrUserInvalidLogin
	}
	if r.Password == "" {
		return ErrUserInvalidPassword
	}
	return nil
}

type UserTokenRenewRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (r *UserTokenRenewRequest) Validate() error {
	if r.RefreshToken == "" {
		return ErrUserAuthInvalidToken
	}
	return nil
}

type UserTokenValidateRequest struct {
	AccessToken string `json:"access_token"`
}

func (r *UserTokenValidateRequest) Validate() error {
	if r.AccessToken == "" {
		return ErrUserAuthInvalidToken
	}
	return nil
}

type UserAuthLogoutDeviceRequest struct {
	Device string `json:"device"`
}

func (r *UserAuthLogoutDeviceRequest) Validate() error {
	if r.Device == "" {
		return ErrUserInvalidDevice
	}
	return nil
}
