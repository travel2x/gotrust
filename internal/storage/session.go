package storage

import (
	"errors"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/kelseyhightower/envconfig"
)

var (
	sessionName = "_gotrust_session"
	Store sessions.Store
)

type SessionConfig struct {
	Key []byte `envconfig:"GOTRUST_SESSION_KEY"`
}

func init() {
	var sessionConfig SessionConfig
	if err := envconfig.Process("GOTRUST_SESSION_KEY"); err != nil || len(sessionConfig.Key) == 0 {
		sessionConfig.Key = securecookie.GenerateRandomKey(32)
	}
	Store = sessions.NewCookieStore(sessionConfig.Key)
}

func StoreInSession(key, value string, w http.ResponseWriter, r *http.Request) error {
	session, _ := Store.New(r, sessionName)
	session.Values[key] = value
	return session.Save(r, w)
}

func GetFromSession(key string, r *http.Request) (string, error) {
	session, _ := Store.Get(r, sessionName)
	value, ok := session.Values[key]
	if !ok {
		return "", errors.New("session could not be found for this request")
	}
	return value.(string), nil
}