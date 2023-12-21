package api

import (
	"context"
	"fmt"
	"github.com/travel2x/gotrust/internal/api/provider"
	"github.com/travel2x/gotrust/internal/models"
	"net/http"
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

func (a *API) GetExternalProviderRedirectURL(w http.ResponseWriter, r *http.Request, linkingTargetUser *models.User) (string, error) {
	return "", nil
}

func (a *API) ExternalProviderCallback(w http.ResponseWriter, r *http.Request) error {
	return nil
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
