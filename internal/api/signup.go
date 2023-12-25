package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/fatih/structs"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/travel2x/gotrust/internal/api/provider"
	"github.com/travel2x/gotrust/internal/api/sms_provider"
	"github.com/travel2x/gotrust/internal/models"
	"github.com/travel2x/gotrust/internal/storage"
	"github.com/travel2x/gotrust/internal/utilities"
	"net/http"
	"time"
)

type SignupParams struct {
	Email               string                 `json:"email"`
	Phone               string                 `json:"phone"`
	Password            string                 `json:"password"`
	Data                map[string]interface{} `json:"data"`
	Provider            string                 `json:"-"`
	Aud                 string                 `json:"-"`
	Channel             string                 `json:"channel"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
	CodeChallenge       string                 `json:"code_challenge"`
}

func (p *SignupParams) ConfigureDefaults() {
	if p.Email != "" {
		p.Provider = "email"
	} else if p.Phone != "" {
		p.Provider = "phone"
	}
	if p.Data == nil {
		p.Data = make(map[string]interface{})
	}

	// For backwards compatibility, we default to SMS if params Channel is not specified
	if p.Phone != "" && p.Channel == "" {
		p.Channel = sms_provider.SMSProvider
	}
}

func (s *SignupParams) ToUserModel(isSSOUser bool) (user *models.User, err error) {
	switch s.Provider {
	case "email":
		user, err = models.NewUser("", s.Email, s.Password, s.Aud, s.Data)
	case "phone":
		user, err = models.NewUser(s.Phone, "", s.Password, s.Aud, s.Data)
	default:
		// handles external provider case
		user, err = models.NewUser("", s.Email, s.Password, s.Aud, s.Data)
	}
	if err != nil {
		err = internalServerError("Database error creating user").WithInternalError(err)
		return
	}
	user.IsSSOUser = isSSOUser
	if user.AppMetaData == nil {
		user.AppMetaData = make(map[string]interface{})
	}
	user.Identities = make([]models.Identity, 0)

	// TODO: Deprecate "provider" field
	user.AppMetaData["provider"] = s.Provider

	user.AppMetaData["providers"] = []string{s.Provider}
	if s.Password == "" {
		user.EncryptedPassword = ""
	}
	return
}

func (a *API) SignupNewUser(ctx context.Context, conn *storage.Connection, user *models.User) (*models.User, error) {
	config := a.config

	err := conn.Transaction(func(tx *storage.Connection) error {
		var transactionError error
		if transactionError = tx.Create(user); transactionError != nil {
			return internalServerError("Database error saving new user").WithInternalError(transactionError)
		}
		if transactionError = user.SetRole(tx, config.JWT.DefaultGroupName); transactionError != nil {
			return internalServerError("Database error updating user").WithInternalError(transactionError)
		}
		// we will trigger event hook after the transaction is committed
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = conn.Eager().Load(user)
	if err != nil {
		return nil, internalServerError("Database error loading user after sign-up").WithInternalError(err)
	}
	return user, nil
}

func (a *API) Signup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)
	params := &SignupParams{}

	if config.DisableSignup {
		return forbiddenError("Signups not allowed for this instance")
	}

	body, err := utilities.GetBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}
	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read Signup params: %v", err)
	}

	params.ConfigureDefaults()
	if err := a.ValidateSignupParams(ctx, params); err != nil {
		fmt.Println("Signup::Log::ValidateSignupParams ", err)
		return err
	}

	var codeChallengeMethod models.CodeChallengeMethod
	flowType := getFlowFromChallenge(params.CodeChallenge)

	if isPKCEFlow(flowType) {
		if codeChallengeMethod, err = models.ParseCodeChallengeMethod(params.CodeChallengeMethod); err != nil {
			return err
		}
	}

	var user *models.User
	var grantParams models.GrantParams

	grantParams.FillGrantParams(r)
	params.Aud = a.requestAud(ctx, r)

	switch params.Provider {
	case "email":
		if !config.External.Email.Enabled {
			return badRequestError("Email signups are disabled")
		}
		params.Email, err = validateEmail(params.Email)
		if err != nil {
			return err
		}
		user, err = models.IsDuplicatedEmail(db, params.Email, params.Aud, nil)
	case "phone":
		if !config.External.Phone.Enabled {
			return badRequestError("Phone signups are disabled")
		}
		params.Phone, err = validatePhone(params.Phone)
		if err != nil {
			return err
		}
		user, err = models.FindUserByPhoneAndAudience(db, params.Phone, params.Aud)
	default:
		return invalidSignupError(config)
	}

	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	var signupUser *models.User
	if user == nil {
		signupUser, err = params.ToUserModel(false)
		if err != nil {
			return err
		}
	}
	err = db.Transaction(func(tx *storage.Connection) error {
		var transactionErr error
		if user != nil {
			if (params.Provider == "email" && user.IsConfirmed()) ||
				(params.Provider == "phone" && user.IsPhoneConfirmed()) {
				return UserExistsError
			}
			// do not update the user because we can't be sure of their claimed identity
		} else {
			user, transactionErr = a.SignupNewUser(ctx, tx, signupUser)
			if transactionErr != nil {
				return transactionErr
			}
			identity, err := a.CreateNewIdentity(tx, user, params.Provider, structs.Map(provider.Claims{
				Subject: user.ID.String(),
				Email:   user.GetEmail(),
			}))
			if err != nil {
				return err
			}
			user.Identities = []models.Identity{*identity}
		}
		if params.Provider == "email" && !user.IsConfirmed() {
			if config.Mailer.Autoconfirm {
				if transactionErr = models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", map[string]interface{}{
					"provider": params.Provider,
				}); transactionErr != nil {
					return transactionErr
				}
				// we will trigger event hook after the transaction is committed (in the future)
				if transactionErr = user.Confirm(tx); transactionErr != nil {
					return internalServerError("Database error updating user").WithInternalError(transactionErr)
				}
				// we will trigger event hook after the transaction is committed (in the future)
				if transactionErr = user.ConfirmPhone(tx); transactionErr != nil {
					return internalServerError("Database error updating user").WithInternalError(transactionErr)
				}
			} else {
				// create mailer and send confirmation email
				fmt.Println("Signup::Log::codeChallengeMethod ", codeChallengeMethod)
				return notImplementedError("Email confirmation not implemented")
			}
		} else if params.Provider == "phone" && !user.IsPhoneConfirmed() {
			if config.Sms.Autoconfirm {
				if transactionErr = models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", map[string]interface{}{
					"provider": params.Provider,
					"channel":  params.Channel,
				}); transactionErr != nil {
					return transactionErr
				}
			} else {
				// create an sms provider and send confirmation sms
				return notImplementedError("Phone confirmation not implemented")
			}
		}
		return nil
	})

	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every minute")
		}
		if errors.Is(err, UserExistsError) {
			err = db.Transaction(func(tx *storage.Connection) error {
				if transactionErr := models.NewAuditLogEntry(r, tx, user, models.UserRepeatedSignUpAction, "", map[string]interface{}{
					"provider": params.Provider,
				}); transactionErr != nil {
					return transactionErr
				}
				return nil
			})
			if err != nil {
				return err
			}
			if config.Mailer.Autoconfirm || config.Sms.Autoconfirm {
				return badRequestError("User already registered")
			}
			sanitizedUser, err := sanitizeUser(user, params)
			if err != nil {
				return err
			}
			return sendJSON(w, http.StatusOK, sanitizedUser)
		}
		return err
	}

	// handle case where Mailer auto confirm is true or Phone auto confirm is true
	if user.IsConfirmed() || user.IsPhoneConfirmed() {
		var token *AccessTokenResponse
		err = db.Transaction(func(tx *storage.Connection) error {
			var transactionErr error
			if transactionErr = models.NewAuditLogEntry(r, tx, user, models.LoginAction, "", map[string]interface{}{
				"provider": params.Provider,
			}); transactionErr != nil {
				return transactionErr
			}
			// we will trigger event hook after the transaction is committed (in the future)
			token, transactionErr = a.IssueRefreshToken(ctx, tx, user, models.PasswordGrant, grantParams)
			if transactionErr != nil {
				return transactionErr
			}
			if transactionErr = a.SetCookieTokens(config, token, false, w); transactionErr != nil {
				return internalServerError("Failed to set JWT cookie. %s", transactionErr)
			}
			return nil
		})
		if err != nil {
			return err
		}
		// we will set metrics after the transaction is committed (in the future)
		return sendJSON(w, http.StatusOK, token)
	}

	if user.HasBeenInvited() {
		// Remove sensitive fields
		user.UserMetaData = map[string]interface{}{}
		user.Identities = []models.Identity{}
	}
	return sendJSON(w, http.StatusOK, user)
}

func (a *API) ValidateSignupParams(ctx context.Context, params *SignupParams) error {
	config := a.config
	fmt.Printf("Signup::Log::ValidateSignupParams::params %v\n", params.Email != "" && params.Phone != "")
	if params.Password == "" {
		return unprocessableEntityError("Signup requires a valid password")
	}
	if err := a.CheckPasswordStrength(ctx, params.Password); err != nil {
		return err
	}
	if params.Email != "" && params.Phone != "" {
		return unprocessableEntityError("Only an email address or phone number should be provided on signup.")
	}
	if params.Provider == "phone" && !sms_provider.IsValidMessageChannel(params.Channel, config.Sms.Provider) {
		return badRequestError(InvalidChannelError)
	}
	// PKCE aren't needed as phone signups already return access token in body
	if params.Phone != "" && params.CodeChallenge != "" {
		return badRequestError("PKCE not supported for phone signups")
	}
	if err := validatePKCEParams(params.CodeChallengeMethod, params.CodeChallenge); err != nil {
		return err
	}
	return nil
}

func sanitizeUser(u *models.User, params *SignupParams) (*models.User, error) {
	now := time.Now()
	id := uuid.Must(uuid.NewV4())

	u.ID = id
	u.CreatedAt, u.UpdatedAt, u.ConfirmationSentAt = now, now, &now
	u.LastSignInAt, u.ConfirmedAt, u.EmailConfirmedAt, u.PhoneConfirmedAt = nil, nil, nil, nil
	u.Identities = make([]models.Identity, 0)
	u.UserMetaData = params.Data
	u.Aud = params.Aud

	// sanitize app_metadata
	u.AppMetaData = map[string]interface{}{
		"provider":  params.Provider,
		"providers": []string{params.Provider},
	}

	// sanitize param fields
	switch params.Provider {
	case "email":
		u.Phone = ""
	case "phone":
		u.Email = ""
	default:
		u.Phone, u.Email = "", ""
	}
	return u, nil
}
