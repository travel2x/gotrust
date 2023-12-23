package models

import (
	"context"
	"database/sql"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/travel2x/gotrust/internal/crypto"
	"github.com/travel2x/gotrust/internal/storage"
	"strings"
	"time"
)

type User struct {
	ID uuid.UUID `json:"id" db:"id"`

	Aud       string             `json:"aud" db:"aud"`
	Role      string             `json:"role" db:"role"`
	Email     storage.NullString `json:"email" db:"email"`
	IsSSOUser bool               `json:"-" db:"is_sso_user"`

	EncryptedPassword string     `json:"-" db:"encrypted_password"`
	EmailConfirmedAt  *time.Time `json:"email_confirmed_at,omitempty" db:"email_confirmed_at"`
	InvitedAt         *time.Time `json:"invited_at,omitempty" db:"invited_at"`

	Phone            storage.NullString `json:"phone" db:"phone"`
	PhoneConfirmedAt *time.Time         `json:"phone_confirmed_at,omitempty" db:"phone_confirmed_at"`

	ConfirmationToken  string     `json:"-" db:"confirmation_token"`
	ConfirmationSentAt *time.Time `json:"confirmation_sent_at,omitempty" db:"confirmation_sent_at"`

	// For backward compatibility only. Use EmailConfirmedAt or PhoneConfirmedAt instead.
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty" db:"confirmed_at" rw:"r"`

	RecoveryToken  string     `json:"-" db:"recovery_token"`
	RecoverySentAt *time.Time `json:"recovery_sent_at,omitempty" db:"recovery_sent_at"`

	EmailChangeTokenCurrent  string     `json:"-" db:"email_change_token_current"`
	EmailChangeTokenNew      string     `json:"-" db:"email_change_token_new"`
	EmailChange              string     `json:"new_email,omitempty" db:"email_change"`
	EmailChangeSentAt        *time.Time `json:"email_change_sent_at,omitempty" db:"email_change_sent_at"`
	EmailChangeConfirmStatus int        `json:"-" db:"email_change_confirm_status"`

	PhoneChangeToken  string     `json:"-" db:"phone_change_token"`
	PhoneChange       string     `json:"new_phone,omitempty" db:"phone_change"`
	PhoneChangeSentAt *time.Time `json:"phone_change_sent_at,omitempty" db:"phone_change_sent_at"`

	ReauthenticationToken  string     `json:"-" db:"reauthentication_token"`
	ReauthenticationSentAt *time.Time `json:"reauthentication_sent_at,omitempty" db:"reauthentication_sent_at"`

	LastSignInAt *time.Time `json:"last_sign_in_at,omitempty" db:"last_sign_in_at"`

	AppMetaData  JSONMap `json:"app_metadata" db:"raw_app_meta_data"`
	UserMetaData JSONMap `json:"user_metadata" db:"raw_user_meta_data"`

	Factors    []Factor   `json:"factors,omitempty" has_many:"factors"`
	Identities []Identity `json:"identities" has_many:"identities"`

	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	BannedUntil *time.Time `json:"banned_until,omitempty" db:"banned_until"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`

	DONTUSEINSTANCEID uuid.UUID `json:"-" db:"instance_id"`
}

func (User) TableName() string {
	return "users"
}

func NewUser(email, phone, password, aud string, userData map[string]interface{}) (*User, error) {
	passwordHash := ""
	if password != "" {
		pw, err := crypto.GenerateFromPassword(context.Background(), password)
		if err != nil {
			return nil, err
		}
		passwordHash = pw
	}
	if userData == nil {
		userData = make(map[string]interface{})
	}
	return &User{
		ID:                uuid.Must(uuid.NewV4()),
		Aud:               aud,
		Email:             storage.NullString(strings.ToLower(email)),
		Phone:             storage.NullString(phone),
		UserMetaData:      userData,
		EncryptedPassword: passwordHash,
	}, nil
}

func (u *User) BeforeSave(tx *pop.Connection) error {
	if u.EmailConfirmedAt != nil && u.EmailConfirmedAt.IsZero() {
		u.EmailConfirmedAt = nil
	}
	if u.PhoneConfirmedAt != nil && u.PhoneConfirmedAt.IsZero() {
		u.PhoneConfirmedAt = nil
	}
	if u.InvitedAt != nil && u.InvitedAt.IsZero() {
		u.InvitedAt = nil
	}
	if u.ConfirmationSentAt != nil && u.ConfirmationSentAt.IsZero() {
		u.ConfirmationSentAt = nil
	}
	if u.RecoverySentAt != nil && u.RecoverySentAt.IsZero() {
		u.RecoverySentAt = nil
	}
	if u.EmailChangeSentAt != nil && u.EmailChangeSentAt.IsZero() {
		u.EmailChangeSentAt = nil
	}
	if u.PhoneChangeSentAt != nil && u.PhoneChangeSentAt.IsZero() {
		u.PhoneChangeSentAt = nil
	}
	if u.ReauthenticationSentAt != nil && u.ReauthenticationSentAt.IsZero() {
		u.ReauthenticationSentAt = nil
	}
	if u.LastSignInAt != nil && u.LastSignInAt.IsZero() {
		u.LastSignInAt = nil
	}
	if u.BannedUntil != nil && u.BannedUntil.IsZero() {
		u.BannedUntil = nil
	}
	return nil
}

// IsConfirmed checks if a user has already been
// registered and confirmed.
func (u *User) IsConfirmed() bool {
	return u.EmailConfirmedAt != nil
}

// HasBeenInvited checks if user has been invited
func (u *User) HasBeenInvited() bool {
	return u.InvitedAt != nil
}

// IsPhoneConfirmed checks if a user's phone has already been
// registered and confirmed.
func (u *User) IsPhoneConfirmed() bool {
	return u.PhoneConfirmedAt != nil
}

//// SetRole sets the users Role to roleName
//func (u *User) SetRole(tx *storage.Connection, roleName string) error {
//	u.Role = strings.TrimSpace(roleName)
//	return tx.UpdateOnly(u, "role")
//}

// HasRole returns true when the users role is set to roleName
func (u *User) HasRole(roleName string) bool {
	return u.Role == roleName
}

// GetEmail returns the user's email as a string
func (u *User) GetEmail() string {
	return string(u.Email)
}

// GetPhone returns the user's phone number as a string
func (u *User) GetPhone() string {
	return string(u.Phone)
}

func FindUserByID(tx *storage.Connection, id uuid.UUID) (*User, error) {
	return findUser(tx, "instance_id = ? and id = ?", uuid.Nil, id)
}

func FindUserByConfirmationToken(tx *storage.Connection, token string) (*User, error) {
	user, err := findUser(tx, "confirmation_token = ? and is_sso_user = false", token)
	if err != nil {
		return nil, ConfirmationTokenNotFoundError{}
	}
	return user, nil
}

func findUser(tx *storage.Connection, query string, args ...interface{}) (*User, error) {
	u := &User{}
	if err := tx.Eager().Q().Where(query, args...).First(u); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, UserNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding user")
	}
	return u, nil
}
