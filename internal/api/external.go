package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/fatih/structs"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	"github.com/travel2x/gotrust/internal/api/provider"
	"github.com/travel2x/gotrust/internal/models"
	"github.com/travel2x/gotrust/internal/observability"
	"github.com/travel2x/gotrust/internal/storage"
	"github.com/travel2x/gotrust/internal/utilities"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ExternalProviderClaims struct {
	AuthMicroserviceClaims
	Provider        string `json:"provider"`
	InviteToken     string `json:"invite_token,omitempty"`
	Referrer        string `json:"referrer,omitempty"`
	FlowStateID     string `json:"flow_state_id"`
	LinkingTargetID string `json:"linking_target_id,omitempty"`
}

func (a *API) ExternalProviderRedirect(w http.ResponseWriter, r *http.Request) error {
	redirectURL, err := a.GetExternalProviderRedirectURL(w, r, nil)
	if err != nil {
		return err
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

func (a *API) ExternalProviderCallback(w http.ResponseWriter, r *http.Request) error {
	redirectURL := a.getExternalRedirectURL(r)
	u, err := url.Parse(redirectURL)
	if err != nil {
		return err
	}
	a.redirectErrors(a.internalExternalProviderCallback, w, r, u)
	return nil
}

func (a *API) GetExternalProviderRedirectURL(w http.ResponseWriter, r *http.Request, linkingTargetUser *models.User) (string, error) {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	query := r.URL.Query()
	providerType := query.Get("provider")
	scopes := query.Get("scopes")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	p, err := a.Provider(ctx, providerType, scopes)
	if err != nil {
		return "", badRequestError("Unsupported provider: %+v", err).WithInternalError(err)
	}

	inviteToken := query.Get("invite_token")
	if inviteToken != "" {
		_, userErr := models.FindUserByConfirmationToken(db, inviteToken)
		if userErr != nil {
			if models.IsNotFoundError(userErr) {
				return "", notFoundError(userErr.Error())
			}
			return "", internalServerError("Database error finding user").WithInternalError(userErr)
		}
	}

	// TODO: add log more here

	if err := validatePKCEParams(codeChallengeMethod, codeChallenge); err != nil {
		logrus.Error("validate pkce params error: ", err)
		return "", err
	}

	flowType := getFlowFromChallenge(codeChallenge)
	flowStateID := ""

	if flowType == models.PKCEFlow {
		codeChallengeMethodType, err := models.ParseCodeChallengeMethod(codeChallengeMethod)
		if err != nil {
			logrus.Error("parse code challenge method error: ", err)
			return "", err
		}

		flowState, err := models.NewFlowState(providerType, codeChallenge, codeChallengeMethodType, models.OAuth)
		if err != nil {
			logrus.Error("new flow state error: ", err)
			return "", err
		}

		if err := a.db.Create(flowState); err != nil {
			logrus.Error("create flow state error: ", err)
			return "", err
		}
		flowStateID = flowState.ID.String()
	}

	claims := ExternalProviderClaims{
		AuthMicroserviceClaims: AuthMicroserviceClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
			},
			SiteURL:    config.SiteURL,
			InstanceID: uuid.Nil.String(),
		},
		Provider:    providerType,
		InviteToken: inviteToken,
		Referrer:    utilities.GetReferrer(r, config),
		FlowStateID: flowStateID,
	}

	if linkingTargetUser != nil {
		// this means that the user is performing manual linking
		claims.LinkingTargetID = linkingTargetUser.ID.String()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.JWT.Secret))

	if err != nil {
		logrus.Error("sign token error: ", err)
		return "", internalServerError("Error creating state").WithInternalError(err)
	}

	authUrlParams := make([]oauth2.AuthCodeOption, 0)
	query.Del("scopes")
	query.Del("provider")
	query.Del("code_challenge")
	query.Del("code_challenge_method")

	for key := range query {
		if key == "workos_provider" {
			// See https://workos.com/docs/reference/sso/authorize/get
			authUrlParams = append(authUrlParams, oauth2.SetAuthURLParam("provider", query.Get(key)))
		} else {
			authUrlParams = append(authUrlParams, oauth2.SetAuthURLParam(key, query.Get(key)))
		}
	}
	authURL := p.AuthCodeURL(tokenString, authUrlParams...)
	return authURL, nil
}

func (a *API) Provider(ctx context.Context, name string, scopes string) (provider.Provider, error) {
	config := a.config
	name = strings.ToLower(name)

	switch name {
	case "apple":
		return provider.NewAppleProvider(ctx, config.External.Apple)
	case "facebook":
		return provider.NewFacebookProvider(config.External.Facebook, scopes)
	case "google":
		return provider.NewGoogleProvider(ctx, config.External.Google, scopes)
	case "linkedin":
		return provider.NewLinkedinProvider(config.External.Linkedin, scopes)
	case "twitter":
		return provider.NewTwitterProvider(config.External.Twitter, scopes)
	//case "github":
	//	return provider.NewGithubProvider(config.External.Github, scopes)
	//case "linkedin_oidc":
	//	return provider.NewLinkedinOIDCProvider(config.External.LinkedinOIDC, scopes)
	default:
		return nil, fmt.Errorf("provider %s could not be found", name)
	}
}

func (a *API) internalExternalProviderCallback(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	var grantParams models.GrantParams
	grantParams.FillGrantParams(r)
	providerType := getExternalProviderType(ctx)
	data, err := a.handleOAuthCallback(w, r)
	if err != nil {
		return err
	}

	userData := data.userData
	if len(userData.Emails) <= 0 {
		return badRequestError("No email returned from provider")
	}

	userData.Metadata.EmailVerified = false
	providerAccessToken := data.token
	providerRefreshToken := data.refreshToken

	for _, email := range userData.Emails {
		userData.Metadata.Email = email.Email
		userData.Metadata.EmailVerified = email.Verified
		if email.Primary {
			break
		}
	}

	var flowState *models.FlowState
	if flowStateID := getFlowStateID(ctx); flowStateID != "" {
		flowState, err = models.FindFlowStateByID(a.db, flowStateID)
		if err != nil {
			return err
		}
	}

	var user *models.User
	var token *AccessTokenResponse
	err = db.Transaction(func(tx *storage.Connection) error {
		var transactionErr error

		if targetUser := getTargetUser(ctx); targetUser != nil {
			if user, transactionErr = a.linkIdentityToUser(ctx, tx, userData, providerType); transactionErr != nil {
				return transactionErr
			}
		} else if inviteToken := getInviteToken(ctx); inviteToken != "" {
			if user, transactionErr = a.processInvite(r, ctx, tx, userData, inviteToken, providerType); transactionErr != nil {
				return transactionErr
			}
		} else {
			if user, transactionErr = a.createAccountFromExternalIdentity(r, tx, userData, providerType); transactionErr != nil {
				return transactionErr
			}
		}
		if flowState != nil {
			// This means that the callback is using PKCE
			flowState.ProviderAccessToken = providerAccessToken
			flowState.ProviderRefreshToken = providerRefreshToken
			flowState.UserID = &(user.ID)
			transactionErr = tx.Update(flowState)
		} else {
			token, transactionErr = a.issueRefreshToken(ctx, tx, user, models.OAuth, grantParams)
		}
		if transactionErr != nil {
			return oauthError("server_error", transactionErr.Error())
		}
		return nil
	})
	if err != nil {
		return err
	}

	redirectURL := a.getExternalRedirectURL(r)
	if flowState != nil {
		redirectURL, err = a.prepPKCERedirectURL(redirectURL, flowState.AuthCode)
		if err != nil {
			return err
		}
	} else if token != nil {
		q := url.Values{}
		q.Set("provider_token", providerAccessToken)
		// Because not all providers give out a refresh token
		// See corresponding OAuth2 spec: <https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1>
		if providerRefreshToken != "" {
			q.Set("provider_refresh_token", providerRefreshToken)
		}
		redirectURL = token.AsRedirectURL(redirectURL, q)

		if err := a.setCookieTokens(config, token, false, w); err != nil {
			return internalServerError("Failed to set JWT cookie. %s", err)
		}
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

func (a *API) redirectErrors(handler apiHandler, w http.ResponseWriter, r *http.Request, u *url.URL) {
	ctx := r.Context()
	log := observability.GetLogEntry(r)
	errorID := getRequestID(ctx)
	if err := handler(w, r); err != nil {
		q := getErrorQueryString(err, errorID, u.Query(), log)
		u.RawQuery = q.Encode()
		// TODO: deprecate returning error details in the query fragment
		hd := url.Values{}
		if q.Get("error") != "" {
			hd.Set("error", q.Get("error"))
		}
		if q.Get("error_description") != "" {
			hd.Set("error_description", q.Get("error_description"))
		}
		if q.Get("error_code") != "" {
			hd.Set("error_code", q.Get("error_code"))
		}
		u.Fragment = hd.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}

func (a *API) getExternalRedirectURL(r *http.Request) string {
	ctx := r.Context()
	config := a.config
	if config.External.RedirectURL != "" {
		return config.External.RedirectURL
	}
	if err := getExternalReferrer(ctx); err != "" {
		return err
	}
	return config.SiteURL
}

func (a *API) loadExternalState(ctx context.Context, state string) (context.Context, error) {
	config := a.config
	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err := p.ParseWithClaims(state, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWT.Secret), nil
	})

	if err != nil || claims.Provider == "" {
		return nil, badRequestError("OAuth state parameter invalid: %v", err)
	}
	if claims.InviteToken != "" {
		ctx = withInviteToken(ctx, claims.InviteToken)
	}
	if claims.Referrer != "" {
		ctx = withReferrer(ctx, claims.Referrer)
	}
	if claims.FlowStateID != "" {
		ctx = withFlowStateID(ctx, claims.FlowStateID)
	}
	if claims.LinkingTargetID != "" {
		linkingTargetUserID, err := uuid.FromString(claims.LinkingTargetID)
		if err != nil {
			return nil, badRequestError("invalid target user id")
		}
		u, err := models.FindUserByID(a.db, linkingTargetUserID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return nil, notFoundError("Linking target user not found")
			}
			return nil, internalServerError("Database error loading user").WithInternalError(err)
		}
		ctx = withTargetUser(ctx, u)
	}
	ctx = withExternalProviderType(ctx, claims.Provider)
	return withSignature(ctx, state), nil
}

func getErrorQueryString(err error, errorID string, q url.Values, log logrus.FieldLogger) *url.Values {
	switch e := err.(type) {
	case *HTTPError:
		if str, ok := OAuthErrorMap[e.Code]; ok {
			q.Set("error", str)
		} else {
			q.Set("error", "server_error")
		}
		if e.Code >= http.StatusInternalServerError {
			e.ErrorID = errorID
			log.WithError(e.Cause()).Error(e.Error())
		} else {
			log.WithError(e.Cause()).Info(e.Error())
		}
		q.Set("error_description", e.Message)
		q.Set("error_code", fmt.Sprintf("%d", e.Code))
	case *OAuthError:
		q.Set("error", e.Err)
		q.Set("error_description", e.Description)
		log.WithError(e.Cause()).Info(e.Error())
	case ErrorCause:
		return getErrorQueryString(e.Cause(), errorID, q, log)
	default:
		errorType, errorDescription := "server_error", err.Error()
		// Provide better error messages for certain user-triggered Postgres errors.
		if pgErr := utilities.NewPostgresError(e); pgErr != nil {
			errorDescription = pgErr.Message
			if oauthErrorType, ok := OAuthErrorMap[pgErr.HttpStatusCode]; ok {
				errorType = oauthErrorType
			}
		}
		q.Set("error", errorType)
		q.Set("error_description", errorDescription)

	}
	return &q
}

func (a *API) handleOAuthCallback(w http.ResponseWriter, r *http.Request) (*OAuthProviderData, error) {
	ctx := r.Context()
	providerType := getExternalProviderType(ctx)

	var oAuthResponseData *OAuthProviderData
	var err error
	switch providerType {
	case "twitter":
		return nil, nil // we will implement this later
	default:
		oAuthResponseData, err = a.oAuthCallback(ctx, r, providerType)
	}
	return oAuthResponseData, err
}

func (a *API) createNewIdentity(tx *storage.Connection, user *models.User, providerType string, metadata map[string]interface{}) (*models.Identity, error) {
	identity, err := models.NewIdentity(user, providerType, metadata)
	if err != nil {
		return nil, err
	}

	if terr := tx.Create(identity); terr != nil {
		return nil, internalServerError("Error creating identity").WithInternalError(terr)
	}

	return identity, nil
}

func (a *API) processInvite(r *http.Request, ctx context.Context, tx *storage.Connection, userData *provider.UserProvidedData, inviteToken, providerType string) (*models.User, error) {
	user, err := models.FindUserByConfirmationToken(tx, inviteToken)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(err.Error())
		}
		return nil, internalServerError("Database error finding user").WithInternalError(err)
	}

	var emailData *provider.Email
	var emails []string
	for i, e := range userData.Emails {
		emails = append(emails, e.Email)
		if user.GetEmail() == e.Email {
			emailData = &userData.Emails[i]
			break
		}
	}
	if emailData == nil {
		return nil, badRequestError("Invited email does not match emails from external provider").WithInternalMessage("invited=%s external=%s", user.Email, strings.Join(emails, ", "))
	}

	var identityData map[string]interface{}
	if userData.Metadata != nil {
		identityData = structs.Map(userData.Metadata)
	}
	identity, err := a.createNewIdentity(tx, user, providerType, identityData)
	if err != nil {
		return nil, err
	}
	if err := user.UpdateAppMetaData(tx, map[string]interface{}{
		"provider": providerType,
	}); err != nil {
		return nil, err
	}
	if err := user.UpdateAppMetaDataProviders(tx); err != nil {
		return nil, err
	}
	if err := user.UpdateUserMetaData(tx, identityData); err != nil {
		return nil, internalServerError("Database error updating user").WithInternalError(err)
	}
	if err := models.NewAuditLogEntry(r, tx, user, models.InviteAcceptedAction, "", map[string]interface{}{
		"provider": providerType,
	}); err != nil {
		return nil, err
	}
	// we will trigger event hooks in the future

	/*
		an account with a previously unconfirmed email + password
		combination or phone may exist, so now that there is an
		OAuth identity bound to this user, and since they have not
		confirmed their email or phone, they are unaware that a
		potentially malicious door exists into their account; thus
		the password and phone needs to be removed.
	*/
	if err := user.RemoveUnconfirmedIdentities(tx, identity); err != nil {
		return nil, internalServerError("Error updating user").WithInternalError(err)
	}
	if err := user.Confirm(tx); err != nil {
		return nil, err
	}

	return user, nil
}

func (a *API) createAccountFromExternalIdentity(r *http.Request, tx *storage.Connection, userData *provider.UserProvidedData, providerType string) (*models.User, error) {
	ctx := r.Context()
	config := a.config
	aud := a.requestAud(ctx, r)
	var user *models.User
	var identity *models.Identity
	var identityData map[string]interface{}

	if userData.Metadata != nil {
		identityData = structs.Map(userData.Metadata)
	}

	decision, err := models.DetermineAccountLinking(tx, config, userData.Emails, userData.Metadata.Subject, aud, providerType)
	if err != nil {
		return nil, err
	}

	switch decision.Decision {
	case models.LinkAccount:
		user = decision.User
		if identity, err = a.createNewIdentity(tx, user, providerType, identityData); err != nil {
			return nil, err
		}
		if err = user.UpdateAppMetaDataProviders(tx); err != nil {
			return nil, err
		}
	case models.CreateAccount:
		if config.DisableSignup {
			return nil, forbiddenError("Signups not allowed for this instance")
		}
		params := &SignupParams{
			Provider: providerType,
			Email:    decision.CandidateEmail.Email,
			Aud:      aud,
			Data:     identityData,
		}
		isSSOUser := false
		if strings.HasPrefix(decision.LinkingDomain, "sso:") {
			isSSOUser = true
		}
		// because params above sets no password, this method is not
		// computationally hard, so it can be used within a database transaction
		user, err = params.ToUserModel(isSSOUser)
		if err != nil {
			return nil, err
		}
		if user, err = a.signupNewUser(ctx, tx, user); err != nil {
			return nil, err
		}

		if identity, err = a.createNewIdentity(tx, user, providerType, identityData); err != nil {
			return nil, err
		}
	case models.AccountExists:
		user = decision.User
		identity = decision.Identities[0]
		identity.IdentityData = identityData

		if err = tx.UpdateOnly(identity, "identity_data", "last_sign_in_at"); err != nil {
			return nil, nil
		}
		if err = user.UpdateUserMetaData(tx, identityData); err != nil {
			return nil, err
		}
		if err = user.UpdateAppMetaDataProviders(tx); err != nil {
			return nil, err
		}
	case models.MultipleAccounts:
		return nil, internalServerError(fmt.Sprintf("Multiple accounts with the same email address in the same linking domain detected: %v", decision.LinkingDomain))
	default:
		return nil, internalServerError(fmt.Sprintf("Unknown automatic linking decision: %v", decision.Decision))
	}

	if user.IsBanned() {
		return nil, unauthorizedError("User is unauthorized")
	}
	if !user.IsConfirmed() {
		// The user may have other unconfirmed email + password
		// combination, phone or oauth identities. These identities
		// need to be removed when a new oauth identity is being added
		// to prevent pre-account takeover attacks from happening.
		if err = user.RemoveUnconfirmedIdentities(tx, identity); err != nil {
			return nil, internalServerError("Error updating user").WithInternalError(err)
		}
		if decision.CandidateEmail.Verified || config.Mailer.Autoconfirm {
			if err = models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", map[string]interface{}{
				"provider": providerType,
			}); err != nil {
				return nil, err
			}
			// we will trigger event hooks in the future
			// fall through to auto-confirm and issue token
			if err = user.Confirm(tx); err != nil {
				return nil, internalServerError("Error updating user").WithInternalError(err)
			}
		} else {
			// implement this later
			return nil, errors.New("implement this later")
		}
	} else {
		if err = models.NewAuditLogEntry(r, tx, user, models.LoginAction, "", map[string]interface{}{
			"provider": providerType,
		}); err != nil {
			return nil, err
		}
		// we will trigger event hooks in the future
	}
	return user, nil
}
