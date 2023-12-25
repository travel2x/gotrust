package sms_provider

const SMSProvider = "sms"
const WhatsappProvider = "whatsapp"

func IsValidMessageChannel(channel, smsProvider string) bool {
	switch channel {
	case SMSProvider:
		return true
	case WhatsappProvider:
		return smsProvider == "twilio" || smsProvider == "twilio_verify"
	default:
		return false
	}
}
