package utilities

import (
	"bytes"
	"github.com/travel2x/gotrust/internal/conf"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func GetIPAddress(r *http.Request) string {
	if r.Header != nil {
		xForwardedFor := r.Header.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			ips := strings.Split(xForwardedFor, ",")
			for i := range ips {
				ips[i] = strings.TrimSpace(ips[i])
			}
			for _, ip := range ips {
				if ip != "" {
					parsed := net.ParseIP(ip)
					if parsed == nil {
						continue
					}
					return parsed.String()
				}
			}
		}
	}

	ipPort := r.RemoteAddr
	ip, _, err := net.SplitHostPort(ipPort)
	if err != nil {
		return ipPort
	}
	return ip
}

func GetReferrer(r *http.Request, config *conf.GlobalConfiguration) string {
	// try to get redirect url from query or post data first
	reqReferrer := getRedirectTo(r)
	if IsRedirectURLValid(reqReferrer, config) {
		return reqReferrer
	}
	// instead try referrer header value
	reqReferrer = r.Referer()
	if IsRedirectURLValid(reqReferrer, config) {
		return reqReferrer
	}
	return config.SiteURL
}

func IsRedirectURLValid(redirectURL string, config *conf.GlobalConfiguration) bool {
	if redirectURL == "" {
		return false
	}

	bu, be := url.Parse(config.SiteURL)
	ru, re := url.Parse(redirectURL)

	// As long as the referrer came from the site, we will redirect back there
	if be == nil && re == nil && bu.Hostname() == ru.Hostname() {
		return true
	}

	// For case when user came from mobile app or other permitted resource - redirect back
	for _, pattern := range config.URIAllowListMap {
		if pattern.Match(redirectURL) {
			return true
		}
	}
	return false
}

func getRedirectTo(r *http.Request) (reqReferrer string) {
	reqReferrer = r.Header.Get("redirect_to")
	if reqReferrer == "" {
		return
	}
	if err := r.ParseForm(); err == nil {
		reqReferrer = r.Form.Get("redirect_to")
	}
	return
}

func GetBodyBytes(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	originalBody := r.Body
	defer SafeClose(originalBody)

	buf, err := io.ReadAll(originalBody)
	if err != nil {
		return nil, err
	}

	r.Body = io.NopCloser(bytes.NewReader(buf))

	return buf, nil
}
