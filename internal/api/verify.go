package api

import "net/url"

func (a *API) prepPKCERedirectURL(redirectURL, code string) (string, error) {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
