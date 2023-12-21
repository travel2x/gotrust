package models

import (
	"github.com/gofrs/uuid"
	"github.com/travel2x/gotrust/internal/storage"
	"time"
)

type Identity struct {
	ID           uuid.UUID          `json:"identity_id" db:"id"`
	ProviderID   string             `json:"id" db:"provider_id"`
	UserID       uuid.UUID          `json:"user_id" db:"user_id"`
	IdentityData JSONMap            `json:"identity_data,omitempty" db:"identity_data"`
	Provider     string             `json:"provider" db:"provider"`
	LastSignInAt *time.Time         `json:"last_sign_in_at,omitempty" db:"last_sign_in_at"`
	CreatedAt    time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at" db:"updated_at"`
	Email        storage.NullString `json:"email,omitempty" db:"email" rw:"r"`
}
