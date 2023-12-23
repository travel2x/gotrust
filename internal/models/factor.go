package models

import (
	"github.com/gofrs/uuid"
	"time"
)

const (
	OAuth AuthenticationMethod = iota
	PasswordGrant
	OTP
	TOTPSignIn
	SSOSAML
	Recovery
	Invite
	MagicLink
	EmailSignup
	EmailChange
	TokenRefresh
)

type Factor struct {
	ID           uuid.UUID   `json:"id" db:"id"`
	User         User        `json:"-" belongs_to:"user"`
	UserID       uuid.UUID   `json:"-" db:"user_id"`
	CreatedAt    time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at" db:"updated_at"`
	Status       string      `json:"status" db:"status"`
	FriendlyName string      `json:"friendly_name,omitempty" db:"friendly_name"`
	Secret       string      `json:"-" db:"secret"`
	FactorType   string      `json:"factor_type" db:"factor_type"`
	Challenge    []Challenge `json:"-" has_many:"challenges"`
}

type AuthenticationMethod int

func (authMethod AuthenticationMethod) String() string {
	switch authMethod {
	case OAuth:
		return "oauth"
	case PasswordGrant:
		return "password"
	case OTP:
		return "otp"
	case TOTPSignIn:
		return "totp"
	case Recovery:
		return "recovery"
	case Invite:
		return "invite"
	case SSOSAML:
		return "sso/saml"
	case MagicLink:
		return "magiclink"
	case EmailSignup:
		return "email/signup"
	case EmailChange:
		return "email_change"
	case TokenRefresh:
		return "token_refresh"
	}
	return ""
}
