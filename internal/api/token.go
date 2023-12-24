package api

import (
	"context"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"github.com/travel2x/gotrust/internal/conf"
	"github.com/travel2x/gotrust/internal/models"
	"github.com/travel2x/gotrust/internal/storage"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type AccessTokenClaims struct {
	jwt.StandardClaims
	Email                         string                 `json:"email"`
	Phone                         string                 `json:"phone"`
	AppMetaData                   map[string]interface{} `json:"app_metadata"`
	UserMetaData                  map[string]interface{} `json:"user_metadata"`
	Role                          string                 `json:"role"`
	AuthenticatorAssuranceLevel   string                 `json:"aal,omitempty"`
	AuthenticationMethodReference []models.AMREntry      `json:"amr,omitempty"`
	SessionId                     string                 `json:"session_id,omitempty"`
}

type AccessTokenResponse struct {
	Token                string             `json:"access_token"`
	TokenType            string             `json:"token_type"` // Bearer
	ExpiresIn            int                `json:"expires_in"`
	ExpiresAt            int64              `json:"expires_at"`
	RefreshToken         string             `json:"refresh_token"`
	User                 *models.User       `json:"user"`
	ProviderAccessToken  string             `json:"provider_token,omitempty"`
	ProviderRefreshToken string             `json:"provider_refresh_token,omitempty"`
	WeakPassword         *WeakPasswordError `json:"weak_password,omitempty"`
}

func (r *AccessTokenResponse) AsRedirectURL(redirectURL string, extraParams url.Values) string {
	extraParams.Set("access_token", r.Token)
	extraParams.Set("token_type", r.TokenType)
	extraParams.Set("expires_in", strconv.Itoa(r.ExpiresIn))
	extraParams.Set("expires_at", strconv.FormatInt(r.ExpiresAt, 10))
	extraParams.Set("refresh_token", r.RefreshToken)

	return redirectURL + "#" + extraParams.Encode()
}

func (a *API) SetCookieToken(config *conf.GlobalConfiguration, name string, tokenString string, session bool, w http.ResponseWriter) error {
	if name == "" {
		return errors.New("failed to set cookie, invalid name")
	}
	cookieName := config.Cookie.Key + "-" + name
	exp := time.Second * time.Duration(config.Cookie.Duration)
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    tokenString,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		Domain:   config.Cookie.Domain,
	}
	if !session {
		cookie.Expires = time.Now().Add(exp)
		cookie.MaxAge = config.Cookie.Duration
	}

	http.SetCookie(w, cookie)
	return nil
}

func (a *API) SetCookieTokens(config *conf.GlobalConfiguration, token *AccessTokenResponse, session bool, w http.ResponseWriter) error {
	// don't need to catch error here since we always set the cookie name
	_ = a.SetCookieToken(config, "access-token", token.Token, session, w)
	_ = a.SetCookieToken(config, "refresh-token", token.RefreshToken, session, w)
	return nil
}

func (a *API) issueRefreshToken(ctx context.Context, conn *storage.Connection, user *models.User, authenticationMethod models.AuthenticationMethod, grantParams models.GrantParams) (*AccessTokenResponse, error) {
	config := a.config
	now := time.Now()
	user.LastSignInAt = &now

	var tokenString string
	var expiresAt int64
	var refreshToken *models.RefreshToken

	err := conn.Transaction(func(tx *storage.Connection) error {
		var transactionErr error
		refreshToken, transactionErr = models.GrantAuthenticatedUser(tx, user, grantParams)

		if transactionErr != nil {
			return internalServerError("Database error granting user").WithInternalError(transactionErr)
		}
		transactionErr = models.AddClaimToSession(tx, *refreshToken.SessionId, authenticationMethod)
		if transactionErr != nil {
			return transactionErr
		}

		tokenString, expiresAt, transactionErr = a.GenerateAccessToken(ctx, tx, user, refreshToken.SessionId, authenticationMethod)
		if transactionErr != nil {
			httpErr, ok := transactionErr.(*HTTPError)
			if ok {
				return httpErr
			}
			return internalServerError("error generating jwt token").WithInternalError(transactionErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &AccessTokenResponse{
		Token:        tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    config.JWT.Exp,
		ExpiresAt:    expiresAt,
		RefreshToken: refreshToken.Token,
		User:         user,
	}, nil
}

func (a *API) GenerateAccessToken(ctx context.Context, tx *storage.Connection, user *models.User, sessionId *uuid.UUID, authenticationMethod models.AuthenticationMethod) (string, int64, error) {
	config := a.config
	aal, amr := models.AAL1.String(), []models.AMREntry{}
	sid := ""
	if sessionId != nil {
		sid = sessionId.String()
		session, terr := models.FindSessionByID(tx, *sessionId, false)
		if terr != nil {
			return "", 0, terr
		}
		aal, amr, terr = session.CalculateAALAndAMR(tx)
		if terr != nil {
			return "", 0, terr
		}
	}

	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(time.Second * time.Duration(config.JWT.Exp)).Unix()

	claims := &AccessTokenClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   user.ID.String(),
			Audience:  user.Aud,
			IssuedAt:  issuedAt.Unix(),
			ExpiresAt: expiresAt,
			Issuer:    config.JWT.Issuer,
		},
		Email:                         user.GetEmail(),
		Phone:                         user.GetPhone(),
		AppMetaData:                   user.AppMetaData,
		UserMetaData:                  user.UserMetaData,
		Role:                          user.Role,
		SessionId:                     sid,
		AuthenticatorAssuranceLevel:   aal,
		AuthenticationMethodReference: amr,
	}

	var token *jwt.Token
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	if config.JWT.KeyID != "" {
		if token.Header == nil {
			token.Header = make(map[string]interface{})
		}

		token.Header["kid"] = config.JWT.KeyID
	}

	signed, err := token.SignedString([]byte(config.JWT.Secret))
	if err != nil {
		return "", 0, err
	}

	return signed, expiresAt, nil
}
