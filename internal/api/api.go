package api

import (
	"context"
	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/go-chi/chi"
	"github.com/rs/cors"
	"github.com/sebest/xff"
	"github.com/travel2x/gotrust/internal/conf"
	"github.com/travel2x/gotrust/internal/storage"
	"net/http"
	"time"
)

const (
	audHeaderName  = "x-jwt-aud"
	defaultVersion = "unknown version"
)

type API struct {
	handler http.Handler
	db      *storage.Connection
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

func NewAPI(globalConfig *conf.GlobalConfiguration, db *storage.Connection) *API {
	return NewAPIWithVersion(context.Background(), globalConfig, db, defaultVersion)
}

func NewAPIWithVersion(ctx context.Context, globalConfig *conf.GlobalConfiguration, db *storage.Connection, version string) *API {
	api := &API{
		config:  globalConfig,
		db:      db,
		version: version,
	}

	xffmw, _ := xff.Default()
	r := newRouter()

	r.Use(addRequestID(globalConfig))
	r.Use(recovered)
	r.UseBypass(xffmw.Handler)

	r.Get("/health", api.HealthCheck)
	r.Route("/callback", func(r *Router) {
		r.Use(api.IsValidExternalHost)
		r.Use(api.LoadFlowState)

		r.Get("/", api.ExternalProviderCallback)
		r.Post("/", api.ExternalProviderCallback)
	})
	r.Route("/", func(r *Router) {
		r.Use(api.IsValidExternalHost)

		r.Get("/authorize", api.ExternalProviderRedirect) // http://localhost:8000/authorize?provider=google&redirect_to=http://localhost:3000

		sharedLimiter := api.LimitEmailOrPhoneSentHandler()

		r.With(sharedLimiter).With(api.VerifyCaptcha).Post("/signup", api.Signup)
		r.With(sharedLimiter).With(api.VerifyCaptcha).Post("/recover", func(w http.ResponseWriter, r *http.Request) error {
			return notFoundError("Not implemented")
		})
		r.With(sharedLimiter).With(api.VerifyCaptcha).Post("/resend", func(w http.ResponseWriter, r *http.Request) error {
			return notFoundError("Not implemented")
		})
		r.With(sharedLimiter).With(api.VerifyCaptcha).Post("/magic-link", func(w http.ResponseWriter, r *http.Request) error {
			return notFoundError("Not implemented")
		})
		r.With(sharedLimiter).With(api.VerifyCaptcha).Post("/opt", func(w http.ResponseWriter, r *http.Request) error {
			return notFoundError("Not implemented")
		})
		r.With(api.LimitHandler(
			// Allow requests at the specified rate per 5 minutes.
			tollbooth.NewLimiter(api.config.RateLimitTokenRefresh/(60*5), &limiter.ExpirableOptions{
				DefaultExpirationTTL: time.Hour,
			}).SetBurst(30),
		)).With(api.VerifyCaptcha).Post("/token", func(w http.ResponseWriter, r *http.Request) error {
			return notFoundError("Not implemented")
		})
		r.With(api.LimitHandler(nil)).With(api.VerifyCaptcha).Route("/verify", func(r *Router) {
			r.Get("/", func(w http.ResponseWriter, r *http.Request) error {
				return notFoundError("Not implemented")
			})
			r.Post("/", func(w http.ResponseWriter, r *http.Request) error {
				return notFoundError("Not implemented")
			})
		})
		r.With(api.RequireAuthentication).Post("/logout", func(w http.ResponseWriter, r *http.Request) error {
			return notFoundError("Not implemented")
		})
		r.With(api.RequireAuthentication).Route("/user", func(r *Router) {
			r.Get("/", func(w http.ResponseWriter, r *http.Request) error {
				return notFoundError("Not implemented")
			})
			r.With(sharedLimiter).Put("/", func(w http.ResponseWriter, r *http.Request) error {
				return notFoundError("Not implemented")
			})
			r.Route("/identities", func(r *Router) {
				r.Get("/authorize", func(w http.ResponseWriter, r *http.Request) error {
					return notFoundError("Not implemented")
				})
				r.Delete("/{identity_id}", func(w http.ResponseWriter, r *http.Request) error {
					return notFoundError("Not implemented")
				})
			})
		})
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
		Name:        "GoTrust",
		Description: "GoTrust is a user registration and authentication API",
	})
}
