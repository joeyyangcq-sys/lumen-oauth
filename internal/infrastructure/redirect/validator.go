package redirect

import (
	"context"
	"errors"
	"net"
	"net/url"
	"path"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/ports"
)

var (
	ErrInvalidRedirectURI = errors.New("invalid redirect_uri")
	ErrRedirectNotAllowed = errors.New("redirect_uri not allowed")
)

type Config struct {
	LoopbackEnabled bool
	LoopbackPaths   []string
	CustomSchemes   []string
	HostedHTTPS     []string
}

type Validator struct {
	Config Config
}

var _ ports.RedirectURIValidator = Validator{}

func (v Validator) Validate(_ context.Context, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "*") {
		return "", ErrInvalidRedirectURI
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" && !isCustomScheme(u.Scheme) {
		return "", ErrInvalidRedirectURI
	}
	if u.Fragment != "" {
		return "", ErrInvalidRedirectURI
	}
	u.Path = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))

	if v.isAllowedCustomScheme(u) || v.isAllowedHostedHTTPS(u) || v.isAllowedLoopback(u) {
		return u.String(), nil
	}
	return "", ErrRedirectNotAllowed
}

func (v Validator) isAllowedLoopback(u *url.URL) bool {
	if !v.Config.LoopbackEnabled || u.Scheme != "http" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return false
	}
	for _, allowedPath := range normalizedPaths(v.Config.LoopbackPaths) {
		if u.Path == allowedPath {
			return true
		}
	}
	return false
}

func (v Validator) isAllowedHostedHTTPS(u *url.URL) bool {
	if u.Scheme != "https" {
		return false
	}
	candidate := stripDefaultPort(*u)
	for _, raw := range v.Config.HostedHTTPS {
		allowed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || allowed.Scheme != "https" || allowed.Fragment != "" {
			continue
		}
		*allowed = stripDefaultPort(*allowed)
		if sameRedirect(candidate, *allowed) {
			return true
		}
	}
	return false
}

func (v Validator) isAllowedCustomScheme(u *url.URL) bool {
	if !isCustomScheme(u.Scheme) {
		return false
	}
	for _, raw := range v.Config.CustomSchemes {
		allowed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if sameRedirect(*u, *allowed) {
			return true
		}
	}
	return false
}

func normalizedPaths(paths []string) []string {
	if len(paths) == 0 {
		return []string{"/callback"}
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, path.Clean("/"+strings.TrimPrefix(p, "/")))
	}
	return out
}

func sameRedirect(a, b url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Host, b.Host) &&
		a.Path == b.Path &&
		a.RawQuery == b.RawQuery
}

func stripDefaultPort(u url.URL) url.URL {
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}
	return u
}

func isCustomScheme(scheme string) bool {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	return scheme != "" && scheme != "http" && scheme != "https"
}
