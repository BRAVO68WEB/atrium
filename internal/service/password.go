package service

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

// PasswordError is a complexity failure. Callers map it to invalid_password.
type PasswordError struct {
	Message string
}

func (e *PasswordError) Error() string {
	if e == nil {
		return "password does not meet the policy"
	}
	return e.Message
}

func passwordError(message string) error {
	defer telemetry.Step("service.passwordError")()
	return &PasswordError{Message: message}
}

// CheckPassword reports the first complexity rule the password misses.
// It does not trim or truncate. Login does not call this.
func CheckPassword(policy config.PasswordPolicy, username, password string) error {
	defer telemetry.Step("service.CheckPassword")()
	if policy.MinLength > 0 && len(password) < policy.MinLength {
		return passwordError(fmt.Sprintf("password must be at least %d characters", policy.MinLength))
	}
	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		return passwordError(fmt.Sprintf("password must be at most %d characters", policy.MaxLength))
	}
	var upper, lower, number, symbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			number = true
		default:
			symbol = true
		}
	}
	if policy.RequireUppercase && !upper {
		return passwordError("password must include an uppercase letter")
	}
	if policy.RequireLowercase && !lower {
		return passwordError("password must include a lowercase letter")
	}
	if policy.RequireNumber && !number {
		return passwordError("password must include a number")
	}
	if policy.RequireSymbol && !symbol {
		return passwordError("password must include a symbol")
	}
	if policy.BlockUsername && username != "" && strings.EqualFold(password, username) {
		return passwordError("password must not match the username")
	}
	return nil
}
