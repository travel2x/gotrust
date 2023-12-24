package api

import (
	"context"
	"github.com/golang-jwt/jwt"
	"github.com/travel2x/gotrust/internal/models"
	"net/url"
)

type contextKey string

func (c contextKey) String() string {
	return "gotrust api context key " + string(c)
}

const (
	tokenKey                = contextKey("jwt")
	requestIDKey            = contextKey("request_id")
	inviteTokenKey          = contextKey("invite_token")
	signatureKey            = contextKey("signature")
	externalProviderTypeKey = contextKey("external_provider_type")
	userKey                 = contextKey("user")
	targetUserKey           = contextKey("target_user")
	factorKey               = contextKey("factor")
	sessionKey              = contextKey("session")
	externalReferrerKey     = contextKey("external_referrer")
	functionHooksKey        = contextKey("function_hooks")
	adminUserKey            = contextKey("admin_user")
	oauthTokenKey           = contextKey("oauth_token") // for OAuth1.0, also known as request token
	oauthVerifierKey        = contextKey("oauth_verifier")
	ssoProviderKey          = contextKey("sso_provider")
	externalHostKey         = contextKey("external_host")
	flowStateKey            = contextKey("flow_state_id")
)

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func withExternalHost(ctx context.Context, u *url.URL) context.Context {
	return context.WithValue(ctx, externalHostKey, u)
}

func withRequestToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, oauthTokenKey, token)
}

func withInviteToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, inviteTokenKey, token)
}

func withReferrer(ctx context.Context, referrer string) context.Context {
	return context.WithValue(ctx, externalReferrerKey, referrer)
}

func withFlowStateID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, flowStateKey, id)
}

func withOAuthVerifier(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, oauthVerifierKey, token)
}

func withExternalProviderType(ctx context.Context, provider string) context.Context {
	return context.WithValue(ctx, externalProviderTypeKey, provider)
}

func withSignature(ctx context.Context, signature string) context.Context {
	return context.WithValue(ctx, signatureKey, signature)
}

func withTargetUser(ctx context.Context, u *models.User) context.Context {
	return context.WithValue(ctx, targetUserKey, u)
}

func getExternalReferrer(ctx context.Context) string {
	obj := ctx.Value(externalReferrerKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

func getRequestID(ctx context.Context) string {
	val := ctx.Value(requestIDKey)
	if val == nil {
		return ""
	}
	return val.(string)
}

func getExternalProviderType(ctx context.Context) string {
	obj := ctx.Value(externalProviderTypeKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

func getFlowStateID(ctx context.Context) string {
	obj := ctx.Value(flowStateKey)
	if obj == nil {
		return ""
	}
	return obj.(string)
}

func getTargetUser(ctx context.Context) *models.User {
	if ctx == nil {
		return nil
	}
	obj := ctx.Value(targetUserKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.User)
}

func getInviteToken(ctx context.Context) string {
	obj := ctx.Value(inviteTokenKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

func getToken(ctx context.Context) *jwt.Token {
	obj := ctx.Value(tokenKey)
	if obj == nil {
		return nil
	}

	return obj.(*jwt.Token)
}

func getClaims(ctx context.Context) *AccessTokenClaims {
	token := getToken(ctx)
	if token == nil {
		return nil
	}
	return token.Claims.(*AccessTokenClaims)
}
