package crypto

import (
	"context"
	"golang.org/x/crypto/bcrypt"
)

type HashCost = int

const (
	// DefaultHashCost represents the default
	// hashing cost for any hashing algorithm.
	DefaultHashCost HashCost = iota

	// QuickHashCost represents the quickest
	// hashing cost for any hashing algorithm,
	QuickHashCost HashCost = iota
)

// PasswordHashCost is the current password hashing cost
// for all new hashes generated with
// GenerateHashFromPassword.
var PasswordHashCost = DefaultHashCost

func CompareHashAndPassword(ctx context.Context, hash, password string) error {
	return nil
}

func GenerateFromPassword(ctx context.Context, password string) (string, error) {
	var hashCost int

	switch PasswordHashCost {
	case QuickHashCost:
		hashCost = bcrypt.MinCost
	default:
		hashCost = bcrypt.DefaultCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), hashCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
