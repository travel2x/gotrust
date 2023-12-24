package api

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt"
	"net/http"
	"net/url"
)

type FunctionHooks map[string][]string

type AuthMicroserviceClaims struct {
	jwt.StandardClaims
	SiteURL       string        `json:"site_url"`
	InstanceID    string        `json:"id"`
	FunctionHooks FunctionHooks `json:"function_hooks"`
}

func (a *API) isValidExternalHost(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	var u *url.URL
	var err error

	ctx := r.Context()
	config := a.config
	baseUrl := config.API.ExternalURL
	xForwardedHost := r.Header.Get("X-Forwarded-Host")
	xForwardedProto := r.Header.Get("X-Forwarded-Proto")

	if xForwardedHost != "" && xForwardedProto != "" {
		baseUrl = fmt.Sprintf("%s://%s", xForwardedProto, xForwardedHost)
	} else if r.URL.Scheme != "" && r.URL.Hostname() != "" {
		baseUrl = fmt.Sprintf("%s://%s", r.URL.Scheme, r.URL.Hostname())
	}
	if u, err = url.ParseRequestURI(baseUrl); err != nil {
		// fallback to the default hostname
		//log := observability.GetLogEntry(req)
		//log.WithField("request_url", baseUrl).Warn(err)
		if u, err = url.ParseRequestURI(config.API.ExternalURL); err != nil {
			return ctx, err
		}
	}
	return withExternalHost(ctx, u), nil
}
