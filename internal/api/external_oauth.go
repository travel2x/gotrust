package api

import (
	"context"
	"net/http"
)

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
