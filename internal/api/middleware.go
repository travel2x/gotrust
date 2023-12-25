package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/golang-jwt/jwt"
	"github.com/travel2x/gotrust/internal/utilities"
	"net/http"
	"net/url"
	"time"
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
	ctx := r.Context()
	config := a.config

	if !config.Security.Captcha.Enabled {
		return ctx, nil
	}
	// we will skip captcha validation if the authorization header contains an admin role (implemented in the future)
	if shouldIgnore := isIgnoreCaptchaRoute(r); shouldIgnore {
		return ctx, nil
	}
	// we will implement this in the future, for now we will skip captcha validation
	return ctx, nil
}

func (a *API) LimitEmailOrPhoneSentHandler() MiddlewareHandler {
	// limit per hour
	emailFreq := a.config.RateLimitEmailSent / (60 * 60)
	smsFreq := a.config.RateLimitSmsSent / (60 * 60)
	methodsShouldLimited := []string{http.MethodPut, http.MethodPost}

	emailLimiter := tollbooth.NewLimiter(emailFreq, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Hour,
	}).SetBurst(int(a.config.RateLimitEmailSent)).SetMethods(methodsShouldLimited)
	phoneLimiter := tollbooth.NewLimiter(smsFreq, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Hour,
	}).SetBurst(int(a.config.RateLimitSmsSent)).SetMethods(methodsShouldLimited)

	return func(w http.ResponseWriter, r *http.Request) (context.Context, error) {
		ctx := r.Context()
		config := a.config
		shouldRateLimitEmail := config.External.Email.Enabled && !config.Mailer.Autoconfirm
		shouldRateLimitPhone := config.External.Phone.Enabled && !config.Sms.Autoconfirm

		if shouldRateLimitEmail || shouldRateLimitPhone {
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				bodyBytes, err := utilities.GetBodyBytes(r)
				if err != nil {
					return ctx, internalServerError("Error invalid request body").WithInternalError(err)
				}

				var requestBody struct {
					Email string `json:"email"`
					Phone string `json:"phone"`
				}
				if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
					return ctx, badRequestError("Error invalid request body").WithInternalError(err)
				}

				if shouldRateLimitEmail {
					if requestBody.Email != "" {
						if err := tollbooth.LimitByKeys(emailLimiter, []string{"email_functions"}); err != nil {
							//emailRateLimitCounter.Add(
							//	r.Context(),
							//	1,
							//	attribute.String("path", r.URL.Path),
							//)
							return ctx, httpError(http.StatusTooManyRequests, "Email rate limit exceeded")
						}
					}
				}
				if shouldRateLimitPhone {
					if requestBody.Phone != "" {
						if err := tollbooth.LimitByKeys(phoneLimiter, []string{"phone_functions"}); err != nil {
							return ctx, httpError(http.StatusTooManyRequests, "Sms rate limit exceeded")
						}
					}
				}
			}
		}
		return ctx, nil
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

func isIgnoreCaptchaRoute(r *http.Request) bool {
	// captcha shouldn't be enabled on the following grant_types
	// id_token, refresh_token, pkce
	if r.URL.Path == "/token" && r.FormValue("grant_type") != "password" {
		return true
	}
	return false
}
