package conf

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type Time struct {
	time.Time
}

type APIConfiguration struct {
	Host            string
	Port            string `envconfig:"PORT" default:"8081"`
	Endpoint        string
	RequestIDHeader string `envconfig:"REQUEST_ID_HEADER"`
	ExternalURL     string `json:"external_url" envconfig:"API_EXTERNAL_URL" required:"true"`
}

type DBConfiguration struct {
	Driver    string `json:"driver" required:"true"`
	URL       string `json:"url" envconfig:"DATABASE_URL" required:"true"`
	Namespace string `json:"namespace" envconfig:"DB_NAMESPACE" default:"auth"`
	// MaxPoolSize defaults to 0 (unlimited).
	MaxPoolSize       int           `json:"max_pool_size" split_words:"true"`
	MaxIdlePoolSize   int           `json:"max_idle_pool_size" split_words:"true"`
	ConnMaxLifetime   time.Duration `json:"conn_max_lifetime,omitempty" split_words:"true"`
	ConnMaxIdleTime   time.Duration `json:"conn_max_idle_time,omitempty" split_words:"true"`
	HealthCheckPeriod time.Duration `json:"health_check_period" split_words:"true"`
	MigrationsPath    string        `json:"migrations_path" split_words:"true" default:"./migrations"`
	CleanupEnabled    bool          `json:"cleanup_enabled" split_words:"true" default:"false"`
}

type OAuthProviderConfiguration struct {
	ClientID       []string `json:"client_id" split_words:"true"`
	Secret         string   `json:"secret"`
	RedirectURI    string   `json:"redirect_uri" split_words:"true"`
	URL            string   `json:"url"`
	ApiURL         string   `json:"api_url" split_words:"true"`
	Enabled        bool     `json:"enabled"`
	SkipNonceCheck bool     `json:"skip_nonce_check" split_words:"true"`
}

type EmailProviderConfiguration struct {
	Enabled bool `json:"enabled" default:"true"`
}

type PhoneProviderConfiguration struct {
	Enabled bool `json:"enabled" default:"false"`
}

type ProviderConfiguration struct {
	Apple                   OAuthProviderConfiguration `json:"apple"`
	Facebook                OAuthProviderConfiguration `json:"facebook"`
	Google                  OAuthProviderConfiguration `json:"google"`
	Linkedin                OAuthProviderConfiguration `json:"linkedin"`
	LinkedinOIDC            OAuthProviderConfiguration `json:"linkedin_oidc" envconfig:"LINKEDIN_OIDC"`
	Twitter                 OAuthProviderConfiguration `json:"twitter"`
	Email                   EmailProviderConfiguration `json:"email"`
	Phone                   PhoneProviderConfiguration `json:"phone"`
	RedirectURL             string                     `json:"redirect_url"`
	AllowedIdTokenIssuers   []string                   `json:"allowed_id_token_issuers" split_words:"true"`
	FlowStateExpiryDuration time.Duration              `json:"flow_state_expiry_duration" split_words:"true"`
	// Azure                   OAuthProviderConfiguration `json:"azure"`
	// Bitbucket               OAuthProviderConfiguration `json:"bitbucket"`
	// Discord                 OAuthProviderConfiguration `json:"discord"`
	// Figma                   OAuthProviderConfiguration `json:"figma"`
	// Fly                     OAuthProviderConfiguration `json:"fly"`
	// Github                  OAuthProviderConfiguration `json:"github"`
	// Gitlab                  OAuthProviderConfiguration `json:"gitlab"`
	// Kakao                   OAuthProviderConfiguration `json:"kakao"`
	// Notion                  OAuthProviderConfiguration `json:"notion"`
	// Keycloak                OAuthProviderConfiguration `json:"keycloak"`
	// Spotify                 OAuthProviderConfiguration `json:"spotify"`
	// Slack                   OAuthProviderConfiguration `json:"slack"`
	// Twitch                  OAuthProviderConfiguration `json:"twitch"`
	// WorkOS                  OAuthProviderConfiguration `json:"workos"`
	// Zoom                    OAuthProviderConfiguration `json:"zoom"`
	// IosBundleId             string        `json:"ios_bundle_id" split_words:"true"`
}

type LoggingConfig struct {
	Level            string                 `mapstructure:"log_level" json:"log_level"`
	File             string                 `mapstructure:"log_file" json:"log_file"`
	DisableColors    bool                   `mapstructure:"disable_colors" split_words:"true" json:"disable_colors"`
	QuoteEmptyFields bool                   `mapstructure:"quote_empty_fields" split_words:"true" json:"quote_empty_fields"`
	TSFormat         string                 `mapstructure:"ts_format" json:"ts_format"`
	Fields           map[string]interface{} `mapstructure:"fields" json:"fields"`
	SQL              string                 `mapstructure:"sql" json:"sql"`
}

type SMTPConfiguration struct {
	MaxFrequency time.Duration `json:"max_frequency" split_words:"true"`
	Host         string        `json:"host"`
	Port         int           `json:"port,omitempty" default:"587"`
	User         string        `json:"user"`
	Pass         string        `json:"pass,omitempty"`
	AdminEmail   string        `json:"admin_email" split_words:"true"`
	SenderName   string        `json:"sender_name" split_words:"true"`
}

func (c *SMTPConfiguration) Validate() error {
	return nil
}

type EmailContentConfiguration struct {
	Invite           string `json:"invite"`
	Confirmation     string `json:"confirmation"`
	Recovery         string `json:"recovery"`
	EmailChange      string `json:"email_change" split_words:"true"`
	MagicLink        string `json:"magic_link" split_words:"true"`
	Reauthentication string `json:"reauthentication"`
}

type MailerConfiguration struct {
	Autoconfirm                 bool `json:"autoconfirm"`
	AllowUnverifiedEmailSignIns bool `json:"allow_unverified_email_sign_ins" split_words:"true" default:"false"`

	Subjects  EmailContentConfiguration `json:"subjects"`
	Templates EmailContentConfiguration `json:"templates"`
	URLPaths  EmailContentConfiguration `json:"url_paths"`

	SecureEmailChangeEnabled bool `json:"secure_email_change_enabled" split_words:"true" default:"true"`

	OtpExp    uint `json:"otp_exp" split_words:"true"`
	OtpLength int  `json:"otp_length" split_words:"true"`
}

type JWTConfiguration struct {
	Secret           string   `json:"secret" required:"true"`
	Exp              int      `json:"exp"`
	Aud              string   `json:"aud"`
	AdminGroupName   string   `json:"admin_group_name" split_words:"true"`
	AdminRoles       []string `json:"admin_roles" split_words:"true"`
	DefaultGroupName string   `json:"default_group_name" split_words:"true"`
	Issuer           string   `json:"issuer"`
	KeyID            string   `json:"key_id" split_words:"true"`
}

type TwilioProviderConfiguration struct {
	AccountSid        string `json:"account_sid" split_words:"true"`
	AuthToken         string `json:"auth_token" split_words:"true"`
	MessageServiceSid string `json:"message_service_sid" split_words:"true"`
	ContentSid        string `json:"content_sid" split_words:"true"`
}

type TwilioVerifyProviderConfiguration struct {
	AccountSid        string `json:"account_sid" split_words:"true"`
	AuthToken         string `json:"auth_token" split_words:"true"`
	MessageServiceSid string `json:"message_service_sid" split_words:"true"`
}

type MessagebirdProviderConfiguration struct {
	AccessKey  string `json:"access_key" split_words:"true"`
	Originator string `json:"originator" split_words:"true"`
}

type TextlocalProviderConfiguration struct {
	ApiKey string `json:"api_key" split_words:"true"`
	Sender string `json:"sender" split_words:"true"`
}

type VonageProviderConfiguration struct {
	ApiKey    string `json:"api_key" split_words:"true"`
	ApiSecret string `json:"api_secret" split_words:"true"`
	From      string `json:"from" split_words:"true"`
}

type SmsProviderConfiguration struct {
	Autoconfirm  bool              `json:"autoconfirm"`
	MaxFrequency time.Duration     `json:"max_frequency" split_words:"true"`
	OtpExp       uint              `json:"otp_exp" split_words:"true"`
	OtpLength    int               `json:"otp_length" split_words:"true"`
	Provider     string            `json:"provider"`
	Template     string            `json:"template"`
	TestOTP      map[string]string `json:"test_otp" split_words:"true"`
	//TestOTPValidUntil Time               `json:"test_otp_valid_until" split_words:"true"`
	//SMSTemplate       *template.Template `json:"-"`

	Twilio       TwilioProviderConfiguration       `json:"twilio"`
	TwilioVerify TwilioVerifyProviderConfiguration `json:"twilio_verify" split_words:"true"`
	Messagebird  MessagebirdProviderConfiguration  `json:"messagebird"`
	Textlocal    TextlocalProviderConfiguration    `json:"textlocal"`
	Vonage       VonageProviderConfiguration       `json:"vonage"`
}

//func (c *SmsProviderConfiguration) GetTestOTP(phone string, now time.Time) (string, bool) {
//	if c.TestOTP != nil && (c.TestOTPValidUntil.Time.IsZero() || now.Before(c.TestOTPValidUntil.Time)) {
//		testOTP, ok := c.TestOTP[phone]
//		return testOTP, ok
//	}
//
//	return "", false
//}

type WebhookConfig struct {
	URL        string   `json:"url"`
	Retries    int      `json:"retries"`
	TimeoutSec int      `json:"timeout_sec"`
	Secret     string   `json:"secret"`
	Events     []string `json:"events"`
}

func (w *WebhookConfig) HasEvent(event string) bool {
	for _, name := range w.Events {
		if event == name {
			return true
		}
	}
	return false
}

type CaptchaConfiguration struct {
	Enabled  bool   `json:"enabled" default:"false"`
	Provider string `json:"provider" default:"hcaptcha"`
	Secret   string `json:"provider_secret"`
}

func (c *CaptchaConfiguration) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Provider != "hcaptcha" && c.Provider != "turnstile" {
		return fmt.Errorf("unsupported captcha provider: %s", c.Provider)
	}

	c.Secret = strings.TrimSpace(c.Secret)

	if c.Secret == "" {
		return errors.New("captcha provider secret is empty")
	}

	return nil
}

type SecurityConfiguration struct {
	Captcha                               CaptchaConfiguration `json:"captcha"`
	RefreshTokenRotationEnabled           bool                 `json:"refresh_token_rotation_enabled" split_words:"true" default:"true"`
	RefreshTokenReuseInterval             int                  `json:"refresh_token_reuse_interval" split_words:"true"`
	UpdatePasswordRequireReauthentication bool                 `json:"update_password_require_reauthentication" split_words:"true"`
	ManualLinkingEnabled                  bool                 `json:"manual_linking_enabled" split_words:"true" default:"false"`
}

func (c *SecurityConfiguration) Validate() error {
	return c.Captcha.Validate()
}

type SessionsConfiguration struct {
	Timebox           *time.Duration `json:"timebox"`
	InactivityTimeout *time.Duration `json:"inactivity_timeout,omitempty" split_words:"true"`

	SinglePerUser bool     `json:"single_per_user" split_words:"true"`
	Tags          []string `json:"tags,omitempty"`
}

func (c *SessionsConfiguration) Validate() error {
	if c.Timebox == nil {
		return nil
	}

	if *c.Timebox <= time.Duration(0) {
		return fmt.Errorf("conf: session timebox duration must be positive when set, was %v", (*c.Timebox).String())
	}

	return nil
}

type CORSConfiguration struct {
	AllowedHeaders []string `json:"allowed_headers" split_words:"true"`
}

func (c *CORSConfiguration) AllAllowedHeaders(defaults []string) []string {
	set := make(map[string]bool)
	for _, header := range defaults {
		set[header] = true
	}

	var result []string
	result = append(result, defaults...)

	for _, header := range c.AllowedHeaders {
		if !set[header] {
			result = append(result, header)
		}

		set[header] = true
	}

	return result
}

type PasswordConfiguration struct {
	MinLength int `json:"min_length" split_words:"true"`

	RequiredCharacters PasswordRequiredCharacters `json:"required_characters" split_words:"true"`

	// HIBP HIBPConfiguration `json:"hibp"`
}

type PasswordRequiredCharacters []string

func (v *PasswordRequiredCharacters) Decode(value string) error {
	parts := strings.Split(value, ":")

	for i := 0; i < len(parts)-1; i += 1 {
		part := parts[i]

		if part == "" {
			continue
		}

		// part ended in escape character, so it should be joined with the next one
		if part[len(part)-1] == '\\' {
			parts[i] = part[0:len(part)-1] + ":" + parts[i+1]
			parts[i+1] = ""
			continue
		}
	}

	for _, part := range parts {
		if part != "" {
			*v = append(*v, part)
		}
	}

	return nil
}
