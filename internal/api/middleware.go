package api

import (
	"context"
	"fmt"
	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
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

func (a *API) IsValidExternalHost(w http.ResponseWriter, r *http.Request) (context.Context, error) {
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

func (a *API) VerifyCaptcha(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	return nil, nil
}

func (a *API) LimitEmailOrPhoneSentHandler() MiddlewareHandler {
	// limit per hour
	emailFreq := a.config.RateLimitEmailSent / (60 * 60)
	smsFreq := a.config.RateLimitSmsSent / (60 * 60)

	fmt.Println(emailFreq, smsFreq)

	return func(w http.ResponseWriter, r *http.Request) (context.Context, error) {
		return nil, nil
	}
}

func (a *API) LimitHandler(lmt *limiter.Limiter) MiddlewareHandler {
	return func(w http.ResponseWriter, r *http.Request) (context.Context, error) {
		c := r.Context()
		if limitHeader := a.config.RateLimitHeader; limitHeader != "" {
			key := r.Header.Get(limitHeader)
			if key == "" {
				// we will add log here in the future
				return c, nil
			} else {
				err := tollbooth.LimitByKeys(lmt, []string{key})
				if err != nil {
					return c, httpError(http.StatusTooManyRequests, "Rate limit exceeded")
				}
			}
		}
		return c, nil
	}
}
