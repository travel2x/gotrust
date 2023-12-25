package api

import (
	"regexp"
	"strings"
)

var e164Format = regexp.MustCompile("^[1-9][0-9]{1,14}$")

const (
	phoneConfirmationOtp     = "confirmation"
	phoneReauthenticationOtp = "reauthentication"
)

func validatePhone(phone string) (string, error) {
	phone = formatPhoneNumber(phone)
	if isValid := validateE164Format(phone); !isValid {
		return "", unprocessableEntityError("Invalid phone number format (E.164 required)")
	}
	return phone, nil
}

func validateE164Format(phone string) bool {
	return e164Format.MatchString(phone)
}

func formatPhoneNumber(phone string) string {
	return strings.ReplaceAll(strings.TrimPrefix(phone, "+"), " ", "")
}
