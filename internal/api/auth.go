package api

import (
	"context"
	"net/http"
)

func (a *API) RequireAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	return nil, nil
}
