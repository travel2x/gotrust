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

func (a *API) isValidExternalHost(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := req.Context()
	config := a.config

	var u *url.URL
	var err error

	baseUrl := config.API.ExternalURL
	xForwardedHost := req.Header.Get("X-Forwarded-Host")
	xForwardedProto := req.Header.Get("X-Forwarded-Proto")
	if xForwardedHost != "" && xForwardedProto != "" {
		baseUrl = fmt.Sprintf("%s://%s", xForwardedProto, xForwardedHost)
	} else if req.URL.Scheme != "" && req.URL.Hostname() != "" {
		baseUrl = fmt.Sprintf("%s://%s", req.URL.Scheme, req.URL.Hostname())
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
