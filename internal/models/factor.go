package models

import (
	"github.com/gofrs/uuid"
	"time"
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
