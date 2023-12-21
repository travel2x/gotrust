package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/travel2x/gotrust/internal/utilities"
	"golang.org/x/oauth2"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var defaultTimeout time.Duration = time.Second * 10

func init() {
	timeoutStr := os.Getenv("GOTRUST_INTERNAL_HTTP_TIMEOUT")
	if timeoutStr != "" {
		if timeout, err := time.ParseDuration(timeoutStr); err != nil {
			log.Fatalf("error loading GOTRUE_INTERNAL_HTTP_TIMEOUT: %v", err.Error())
		} else if timeout != 0 {
			defaultTimeout = timeout
		}
	}
}

type Provider interface {
	AuthCodeURL(string, ...oauth2.AuthCodeOption) string
}

type OAuthProvider interface {
	AuthCodeURL(string, ...oauth2.AuthCodeOption) string
	GetUserData(context.Context, *oauth2.Token) (*UserProvidedData, error)
	GetOAuthToken(string) (*oauth2.Token, error)
}

func chooseHost(base, defaultHost string) string {
	if base == "" {
		return "https://" + defaultHost
	}
	baseLen := len(base)
	if base[baseLen-1] == '/' {
		return base[:baseLen-1]
	}
	return base
}

func makeRequest(ctx context.Context, oauthToken *oauth2.Token, oauthConfig *oauth2.Config, url string, dst interface{}) error {
	client := oauthConfig.Client(ctx, oauthToken)
	client.Timeout = defaultTimeout
	res, err := client.Get(url)
	if err != nil {
		return err
	}
	defer utilities.SafeClose(res.Body)

	bodyBytes, _ := io.ReadAll(res.Body)
	res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return httpError(res.StatusCode, string(bodyBytes))
	}
	if err := json.NewDecoder(res.Body).Decode(dst); err != nil {
		return err
	}
	return nil
}
