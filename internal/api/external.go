package api

import (
	"context"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	"github.com/travel2x/gotrust/internal/api/provider"
	"github.com/travel2x/gotrust/internal/models"
	"net/http"
	"net/url"
	"strings"
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
	url, err := a.GetExternalProviderRedirectURL(w, r, nil)
	if err != nil {
		return err
	}
	http.Redirect(w, r, url, http.StatusFound)
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
	return "", nil
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
	return nil
}

func (a *API) redirectErrors(handler apiHandler, w http.ResponseWriter, r *http.Request, u *url.URL) {
	ctx := r.Context()
	errorID := getRequestID(ctx)
	if err := handler(w, r); err != nil {
		q := getErrorQueryString(err, errorID, u.Query(), nil)
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
		fmt.Printf("linkingTargetUserID: %v", linkingTargetUserID)
		//u, err := models.FindUserByID(a.db, linkingTargetUserID)
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
			// log.WithError(e.Cause()).Error(e.Error())
		} else {
			// log.WithError(e.Cause()).Info(e.Error())
		}
		q.Set("error_description", e.Message)
		q.Set("error_code", fmt.Sprintf("%d", e.Code))
	case *OAuthError:
		q.Set("error", e.Err)
		q.Set("error_description", e.Description)
	// log.WithError(e.Cause()).Info(e.Error())
	case ErrorCause:
		return getErrorQueryString(e.Cause(), errorID, q, log)
	default:
		eType, eDescription := "server_error", err.Error()
		// Provide better error messages for certain user-triggered Postgres errors.
		//if pgErr := utilities.NewPostgresError(e); pgErr != nil {
		//	error_description = pgErr.Message
		//	if oauthErrorType, ok := oauthErrorMap[pgErr.HttpStatusCode]; ok {
		//		error_type = oauthErrorType
		//	}
		//}
		q.Set("error", eType)
		q.Set("error_description", eDescription)

	}
	return &q
}
