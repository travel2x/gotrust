package api

import (
	"context"
	"fmt"
	"github.com/travel2x/gotrust/internal/models"
	"github.com/travel2x/gotrust/internal/storage"
	"net/http"
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

func (s *SignupParams) ConfigureDefaults() {
	if s.Email != "" {
		s.Provider = "email"
	} else if s.Phone != "" {
		s.Provider = "phone"
	}
	if s.Data == nil {
		s.Data = make(map[string]interface{})
	}

	// For backwards compatibility, we default to SMS if params Channel is not specified (we will implement this in the future)

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

	if config.DisableSignup {
		return forbiddenError("Signups not allowed for this instance")
	}
	params := &SignupParams{}
	fmt.Println(params, db)

	return nil
}
