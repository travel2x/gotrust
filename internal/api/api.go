package api

import (
	"context"
	"github.com/go-chi/chi"
	"github.com/rs/cors"
	"github.com/sebest/xff"
	"github.com/travel2x/gotrust/internal/conf"
	"net/http"
	"time"
)

const (
	audHeaderName  = "x-jwt-aud"
	defaultVersion = "unknown version"
)

type API struct {
	handler http.Handler
	db      *struct{}
	config  *conf.GlobalConfiguration
	version string

	overrideTime func() time.Time
}

func (a *API) Now() time.Time {
	if a.overrideTime != nil {
		return a.overrideTime()
	}
	return time.Now()
}

func NewAPI(globalConfig *conf.GlobalConfiguration, db *struct{}) *API {
	return NewAPIWithVersion(context.Background(), globalConfig, db, defaultVersion)
}

func NewAPIWithVersion(ctx context.Context, globalConfig *conf.GlobalConfiguration, db *struct{}, version string) *API {
	api := &API{
		config:  globalConfig,
		db:      db,
		version: version,
	}

	xffmw, _ := xff.Default()
	r := newRouter()
	r.Use(addRequestID(globalConfig))

	r.Use(recoverer)
	r.UseBypass(xffmw.Handler)

	r.Get("/health", api.HealthCheck)
	r.Route("/callback", func(r *Router) {
		r.Use(api.isValidExternalHost)
		r.Use(api.loadFlowState)

		r.Get("/", api.ExternalProviderCallback)
		r.Post("/", api.ExternalProviderCallback)
	})

	corsHandler := cors.New(cors.Options{
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowedHeaders:   globalConfig.CORS.AllAllowedHeaders([]string{"Accept", "Authorization", "Content-Type", "X-Client-IP", "X-Client-Info", audHeaderName}),
		ExposedHeaders:   []string{"X-Total-Count", "Link"},
		AllowCredentials: true,
	})

	api.handler = corsHandler.Handler(chi.ServerBaseContext(ctx, r))
	return api
}

type HealthCheckResponse struct {
	Version     string `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (a *API) HealthCheck(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, HealthCheckResponse{
		Version:     a.version,
		Name:        "GoTrue",
		Description: "GoTrue is a user registration and authentication API",
	})
}
