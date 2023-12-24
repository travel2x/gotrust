package api

import (
	"context"
	"github.com/travel2x/gotrust/internal/api/provider"
	"net/http"
	"net/url"
)

type OAuthProviderData struct {
	userData     *provider.UserProvidedData
	token        string
	refreshToken string
	code         string
}

func (a *API) loadFlowState(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	var state string
	if r.Method == http.MethodPost {
		state = r.FormValue("state")
	} else {
		state = r.URL.Query().Get("state")
	}
	if state == "" {
		return nil, badRequestError("OAuth state parameter missing")
	}

	ctx := r.Context()
	q := r.URL.Query()

	oauthToken := q.Get("oauth_token")
	if oauthToken != "" {
		ctx = withRequestToken(ctx, oauthToken)
	}

	oauthVerifier := q.Get("oauth_verifier")
	if oauthVerifier != "" {
		ctx = withOAuthVerifier(ctx, oauthVerifier)
	}
	return a.loadExternalState(ctx, state)
}

func (a *API) oAuthCallback(ctx context.Context, r *http.Request, providerType string) (*OAuthProviderData, error) {
	var rq url.Values
	if err := r.ParseForm(); r.Method == http.MethodPost && err == nil {
		rq = r.Form
	} else {
		rq = r.URL.Query()
	}

	extError := rq.Get("error")
	if extError != "" {
		return nil, oauthError(extError, rq.Get("error_description"))
	}

	oauthCode := rq.Get("code")
	if oauthCode == "" {
		return nil, badRequestError("Authorization code missing")
	}

	oAuthProvider, err := a.OAuthProvider(ctx, providerType)
	if err != nil {
		return nil, err
	}
	// TODO: add more logs here

	token, err := oAuthProvider.GetOAuthToken(oauthCode)
	if err != nil {
		return nil, internalServerError("Unable to exchange external code: %s", oauthCode).WithInternalError(err)
	}

	userData, err := oAuthProvider.GetUserData(ctx, token)
	if err != nil {
		return nil, internalServerError("Error getting user profile from external provider").WithInternalError(err)
	}

	switch externalProvider := oAuthProvider.(type) {
	case *provider.AppleProvider:
		oauthUser := rq.Get("user")
		if oauthUser == "" {
			err := externalProvider.ParseUser(oauthUser, userData)
			if err != nil {
				return nil, err
			}
		}
	}

	return &OAuthProviderData{
		userData:     userData,
		token:        token.AccessToken,
		refreshToken: token.RefreshToken,
		code:         oauthCode,
	}, nil
}

func (a *API) OAuthProvider(ctx context.Context, providerType string) (provider.OAuthProvider, error) {
	providerCandidate, err := a.Provider(ctx, providerType, "")
	if err != nil {
		return nil, err
	}

	switch p := providerCandidate.(type) {
	case provider.OAuthProvider:
		return p, nil
	default:
		return nil, badRequestError("Unsupported provider type: %T", providerCandidate)
	}
}
