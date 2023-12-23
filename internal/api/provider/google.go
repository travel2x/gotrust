package provider

import (
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"github.com/travel2x/gotrust/internal/conf"
	"golang.org/x/oauth2"
	"strings"
)

const (
	IssuerGoogle           = "https://accounts.google.com"
	UserInfoEndpointGoogle = "https://www.googleapis.com/userinfo/v2/me"
)

var (
	internalIssuerGoogle           = IssuerGoogle
	internalUserInfoEndpointGoogle = UserInfoEndpointGoogle
)

type googleUser struct {
	ID            string `json:"id"`
	Subject       string `json:"sub"`
	Issuer        string `json:"iss"`
	Name          string `json:"name"`
	AvatarURL     string `json:"picture"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	EmailVerified bool   `json:"email_verified"`
	HostedDomain  string `json:"hd"`
}

func (u googleUser) IsEmailVerified() bool {
	return u.VerifiedEmail || u.EmailVerified
}

type googleProvider struct {
	*oauth2.Config

	oidc *oidc.Provider
}

func NewGoogleProvider(ctx context.Context, ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		logrus.Error("validate oauth error: ", err)
		return nil, err
	}

	if ext.URL != "" {
		logrus.Warn("Google OAuth provider has URL config set which is ignored (check GOTRUE_EXTERNAL_GOOGLE_URL)")
	}

	oauthScopes := []string{
		"email",
		"profile",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	oidcProvider, err := oidc.NewProvider(ctx, internalIssuerGoogle)
	if err != nil {
		return nil, err
	}
	return &googleProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes:       oauthScopes,
			RedirectURL:  ext.RedirectURI,
		},
		oidc: oidcProvider,
	}, nil
}

func (p googleProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p googleProvider) GetUserData(ctx context.Context, oauthToken *oauth2.Token) (*UserProvidedData, error) {
	if idToken := oauthToken.Extra("id_token"); idToken != nil {
		_, data, err := ParseIDToken(ctx, p.oidc, &oidc.Config{
			ClientID: p.Config.ClientID,
		}, idToken.(string), ParseIDTokenOptions{
			AccessToken: oauthToken.AccessToken,
		})
		if err != nil {
			return nil, err
		}
		return data, nil
	}

	logrus.Info("Using Google OAuth2 user info endpoint, an ID token was not returned by Google")

	var u googleUser
	err := makeRequest(ctx, oauthToken, p.Config, internalUserInfoEndpointGoogle, &u)
	if err != nil {
		return nil, err
	}

	var data UserProvidedData
	if u.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    u.Email,
			Verified: u.IsEmailVerified(),
			Primary:  true,
		})
	}

	data.Metadata = &Claims{
		Issuer:        internalUserInfoEndpointGoogle,
		Subject:       u.ID,
		Name:          u.Name,
		Picture:       u.AvatarURL,
		Email:         u.Email,
		EmailVerified: u.IsEmailVerified(),

		// To be deprecated
		AvatarURL:  u.AvatarURL,
		FullName:   u.Name,
		ProviderId: u.ID,
	}

	return &data, nil
}

func ResetGoogleProvider() {
	internalIssuerGoogle = IssuerGoogle
	internalUserInfoEndpointGoogle = UserInfoEndpointGoogle
}

func OverrideGoogleProvider(issuer, userInfo string) {
	internalIssuerGoogle = issuer
	internalUserInfoEndpointGoogle = userInfo
}
