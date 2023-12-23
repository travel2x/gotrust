package provider

import (
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"time"
)

type ParseIDTokenOptions struct {
	SkipAccessTokenCheck bool
	AccessToken          string
}

var (
	OverrideVerifiers = make(map[string]func(context.Context, *oidc.Config) *oidc.IDTokenVerifier)
	OverrideClock     func() time.Time
)

func ParseIDToken(ctx context.Context, provider *oidc.Provider, config *oidc.Config, idToken string, options ParseIDTokenOptions) (*oidc.IDToken, *UserProvidedData, error) {
	if config == nil {
		config = &oidc.Config{
			// aud claim check to be performed by other flows
			SkipClientIDCheck: true,
		}
	}

	if OverrideClock != nil {
		clonedConfig := *config
		clonedConfig.Now = OverrideClock
		config = &clonedConfig
	}

	verifier := provider.VerifierContext(ctx, config)
	overrideVerifier, ok := OverrideVerifiers[provider.Endpoint().AuthURL]
	if ok && overrideVerifier != nil {
		verifier = overrideVerifier(ctx, config)
	}

	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, nil, err
	}

	var data *UserProvidedData

	switch token.Issuer {
	case IssuerGoogle:
		token, data, err = parseGoogleIDToken(token)
	default:
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, err
	}

	if !options.SkipAccessTokenCheck && token.AccessTokenHash != "" {
		if err := token.VerifyAccessToken(options.AccessToken); err != nil {
			return nil, nil, err
		}
	}
	return token, data, nil
}

func parseGoogleIDToken(token *oidc.IDToken) (*oidc.IDToken, *UserProvidedData, error) {
	var claims googleUser
	if err := token.Claims(&claims); err != nil {
		return nil, nil, err
	}

	var data UserProvidedData
	if claims.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    claims.Email,
			Verified: claims.IsEmailVerified(),
			Primary:  true,
		})
	}

	data.Metadata = &Claims{
		Issuer:  claims.Issuer,
		Subject: claims.Subject,
		Name:    claims.Name,
		Picture: claims.AvatarURL,

		// To be deprecated
		AvatarURL:  claims.AvatarURL,
		FullName:   claims.Name,
		ProviderId: claims.Subject,
	}

	if claims.HostedDomain != "" {
		data.Metadata.CustomClaims = map[string]any{
			"hd": claims.HostedDomain,
		}
	}

	return token, &data, nil
}
