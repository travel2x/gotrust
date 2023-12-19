package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

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
	oauthToken := r.URL.Query().Get("oauth_token")
	if oauthToken != "" {
		ctx = withRequestToken(ctx, oauthToken)
	}
	oauthVerifier := r.URL.Query().Get("oauth_verifier")
	if oauthVerifier != "" {
		ctx = withOAuthVerifier(ctx, oauthVerifier)
	}
	//return a.loadExternalState(ctx, state) // i will be back to this later
	return ctx, nil
}
