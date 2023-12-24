package conf

import (
	"errors"
	"net/url"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"

	"github.com/gobwas/glob"
)

const defaultMinPasswordLength int = 6
const defaultChallengeExpiryDuration float64 = 300
const defaultFlowStateExpiryDuration time.Duration = 300 * time.Second

type GlobalConfiguration struct {
	API      APIConfiguration
	DB       DBConfiguration
	External ProviderConfiguration
	Logging  LoggingConfig `envconfig:"LOG"`
	SMTP     SMTPConfiguration

	RateLimitHeader       string  `split_words:"true"`
	RateLimitEmailSent    float64 `split_words:"true" default:"30"`
	RateLimitSmsSent      float64 `split_words:"true" default:"30"`
	RateLimitVerify       float64 `split_words:"true" default:"30"`
	RateLimitTokenRefresh float64 `split_words:"true" default:"150"`
	RateLimitSso          float64 `split_words:"true" default:"30"`

	SiteURL         string   `json:"site_url" split_words:"true" required:"true"`
	URIAllowList    []string `json:"uri_allow_list" split_words:"true"`
	URIAllowListMap map[string]glob.Glob
	Password        PasswordConfiguration    `json:"password"`
	JWT             JWTConfiguration         `json:"jwt"`
	Mailer          MailerConfiguration      `json:"mailer"`
	Sms             SmsProviderConfiguration `json:"sms"`
	Webhook         WebhookConfig            `json:"webhook" split_words:"true"`
	Security        SecurityConfiguration    `json:"security"`
	Sessions        SessionsConfiguration    `json:"sessions"`
	DisableSignup   bool                     `json:"disable_signup" split_words:"true"`
	Cookie          struct {
		Key      string `json:"key"`
		Domain   string `json:"domain"`
		Duration int    `json:"duration"`
	} `json:"cookies"`
	CORS CORSConfiguration `json:"cors"`
}

func LoadGlobal(filename string) (*GlobalConfiguration, error) {
	if err := loadEnvironment(filename); err != nil {
		return nil, err
	}

	config := new(GlobalConfiguration)

	if err := envconfig.Process("gotrust", config); err != nil {
		return nil, err
	}
	if err := config.ApplyDefaults(); err != nil {
		return nil, err
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

func loadEnvironment(filename string) error {
	var err error
	if filename != "" {
		err = godotenv.Overload(filename)
	} else {
		err = godotenv.Load()
		if os.IsNotExist(err) {
			return nil
		}
	}
	return err
}

func (c *GlobalConfiguration) ApplyDefaults() error {
	if c.JWT.AdminGroupName == "" {
		c.JWT.AdminGroupName = "admin"
	}

	if c.JWT.AdminRoles == nil || len(c.JWT.AdminRoles) == 0 {
		c.JWT.AdminRoles = []string{"service_role", "aus_admin"}
	}

	if c.JWT.Exp == 0 {
		c.JWT.Exp = 3600
	}

	if c.Mailer.Autoconfirm && c.Mailer.AllowUnverifiedEmailSignIns {
		return errors.New("cannot enable both GOTRUE_MAILER_AUTOCONFIRM and GOTRUE_MAILER_ALLOW_UNVERIFIED_EMAIL_SIGN_INS")
	}

	if c.Mailer.URLPaths.Invite == "" {
		c.Mailer.URLPaths.Invite = "/verify"
	}

	if c.Mailer.URLPaths.Confirmation == "" {
		c.Mailer.URLPaths.Confirmation = "/verify"
	}

	if c.Mailer.URLPaths.Recovery == "" {
		c.Mailer.URLPaths.Recovery = "/verify"
	}

	if c.Mailer.URLPaths.EmailChange == "" {
		c.Mailer.URLPaths.EmailChange = "/verify"
	}

	if c.Mailer.OtpExp == 0 {
		c.Mailer.OtpExp = 86400 // 1 day
	}

	if c.Mailer.OtpLength == 0 || c.Mailer.OtpLength < 6 || c.Mailer.OtpLength > 10 {
		// 6-digit otp by default
		c.Mailer.OtpLength = 6
	}

	if c.SMTP.MaxFrequency == 0 {
		c.SMTP.MaxFrequency = 1 * time.Minute
	}

	if c.Sms.MaxFrequency == 0 {
		c.Sms.MaxFrequency = 1 * time.Minute
	}

	if c.Sms.OtpExp == 0 {
		c.Sms.OtpExp = 60
	}

	if c.Sms.OtpLength == 0 || c.Sms.OtpLength < 6 || c.Sms.OtpLength > 10 {
		// 6-digit otp by default
		c.Sms.OtpLength = 6
	}

	if len(c.Sms.Template) == 0 {
		c.Sms.Template = ""
	}

	if c.Cookie.Key == "" {
		c.Cookie.Key = "sb"
	}

	if c.Cookie.Domain == "" {
		c.Cookie.Domain = ""
	}

	if c.Cookie.Duration == 0 {
		c.Cookie.Duration = 86400
	}

	if c.URIAllowList == nil {
		c.URIAllowList = []string{}
	}

	if c.URIAllowList != nil {
		c.URIAllowListMap = make(map[string]glob.Glob)
		for _, uri := range c.URIAllowList {
			g := glob.MustCompile(uri, '.', '/')
			c.URIAllowListMap[uri] = g
		}
	}

	if c.Password.MinLength < defaultMinPasswordLength {
		c.Password.MinLength = defaultMinPasswordLength
	}
	// if config.MFA.ChallengeExpiryDuration < defaultChallengeExpiryDuration {
	// 	config.MFA.ChallengeExpiryDuration = defaultChallengeExpiryDuration
	// }
	if c.External.FlowStateExpiryDuration < defaultFlowStateExpiryDuration {
		c.External.FlowStateExpiryDuration = defaultFlowStateExpiryDuration
	}

	if len(c.External.AllowedIdTokenIssuers) == 0 {
		c.External.AllowedIdTokenIssuers = append(c.External.AllowedIdTokenIssuers, "https://appleid.apple.com", "https://accounts.google.com")
	}

	return nil
}

// Validate validates all of configuration.
func (c *GlobalConfiguration) Validate() error {
	validateTables := []interface {
		Validate() error
	}{
		&c.Security,
		&c.Sessions,
		&c.API,
		&c.DB,
		//&c.SMTP,
		// &c.Tracing,
		// &c.Metrics,
		// &c.SAML,
		// &c.Hook,
	}

	for _, validatable := range validateTables {
		if err := validatable.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (o *OAuthProviderConfiguration) ValidateOAuth() error {
	if !o.Enabled {
		return errors.New("provider is not enabled")
	}
	if len(o.ClientID) == 0 {
		return errors.New("missing OAuth client ID")
	}
	if o.Secret == "" {
		return errors.New("missing OAuth secret")
	}
	if o.RedirectURI == "" {
		return errors.New("missing redirect URI")
	}
	return nil
}

func (a *APIConfiguration) Validate() error {
	_, err := url.ParseRequestURI(a.ExternalURL)
	if err != nil {
		return err
	}

	return nil
}

func (c *DBConfiguration) Validate() error {
	return nil
}

func (t *TwilioProviderConfiguration) Validate() error {
	if t.AccountSid == "" {
		return errors.New("missing Twilio account SID")
	}
	if t.AuthToken == "" {
		return errors.New("missing Twilio auth token")
	}
	if t.MessageServiceSid == "" {
		return errors.New("missing Twilio message service SID or Twilio phone number")
	}
	return nil
}

func (t *TwilioVerifyProviderConfiguration) Validate() error {
	if t.AccountSid == "" {
		return errors.New("missing Twilio account SID")
	}
	if t.AuthToken == "" {
		return errors.New("missing Twilio auth token")
	}
	if t.MessageServiceSid == "" {
		return errors.New("missing Twilio message service SID or Twilio phone number")
	}
	return nil
}

func (t *MessagebirdProviderConfiguration) Validate() error {
	if t.AccessKey == "" {
		return errors.New("missing Messagebird access key")
	}
	if t.Originator == "" {
		return errors.New("missing Messagebird originator")
	}
	return nil
}

func (t *TextlocalProviderConfiguration) Validate() error {
	if t.ApiKey == "" {
		return errors.New("missing Textlocal API key")
	}
	if t.Sender == "" {
		return errors.New("missing Textlocal sender")
	}
	return nil
}

func (t *VonageProviderConfiguration) Validate() error {
	if t.ApiKey == "" {
		return errors.New("missing Vonage API key")
	}
	if t.ApiSecret == "" {
		return errors.New("missing Vonage API secret")
	}
	if t.From == "" {
		return errors.New("missing Vonage 'from' parameter")
	}
	return nil
}
