package api

import (
	"github.com/badoux/checkmail"
	"github.com/pkg/errors"
	"strings"
)

var (
	MaxFrequencyLimitError error = errors.New("frequency limit reached")
)

func validateEmail(email string) (string, error) {
	if email == "" {
		return email, unprocessableEntityError("Email is required")
	}
	if err := checkmail.ValidateFormat(email); err != nil {
		return "", unprocessableEntityError("Unable to validate email address: " + err.Error())
	}
	return strings.ToLower(email), nil
}
