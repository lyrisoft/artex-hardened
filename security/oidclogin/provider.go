// Package oidclogin implements a human OIDC authorization-code login boundary.
// It is not mounted by the legacy ARTEX server. Authentication is not workspace
// authorization, and this package must not be placed in front of unscoped routes.
package oidclogin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	maxProviderResponse = 1 << 20
	providerTimeout     = 10 * time.Second
)

var errProviderResponseTooLarge = errors.New("OIDC provider response too large")

// Config is an operator-controlled provider configuration. AllowedOrigins must
// name every HTTPS origin used by discovery, authorization, token and JWKS
// endpoints. It is never derived from a request or from untrusted token claims.
// Roots is optional and supports separately provisioned private trust roots.
type Config struct {
	Issuer, ClientID, ClientSecret, RedirectURL string
	AllowedOrigins                              []string
	Roots                                       *x509.CertPool
	ReturnPath                                  string
	SessionTTL                                  time.Duration
}

// HumanResolver resolves an already verified issuer and subject to a currently
// enabled persisted human. It must not create principals or memberships.
type HumanResolver interface {
	ResolveHuman(context.Context, string, string) (Human, error)
}

// Human is an already provisioned human identity and its current revocation
// generation. Both fields must be rechecked before using an existing session.
type Human struct {
	ID, AuthEpoch int64
}

// New discovers a single explicitly configured provider. It performs network
// I/O only when called; no package initialization or legacy server route calls
// it. Caller approval and deployment review are required before real use.
func New(ctx context.Context, cfg Config, resolver HumanResolver) (*Flow, error) {
	if ctx == nil || resolver == nil || strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientID) != cfg.ClientID || len(cfg.ClientID) > 1024 || len(cfg.ClientSecret) > 4096 {
		return nil, errors.New("invalid OIDC configuration")
	}
	issuer, err := parseHTTPSURL(cfg.Issuer)
	if err != nil || issuer.RawQuery != "" {
		return nil, errors.New("invalid OIDC issuer")
	}
	redirect, err := parseHTTPSURL(cfg.RedirectURL)
	if err != nil || redirect.RawQuery != "" || redirect.Path == "" {
		return nil, errors.New("invalid OIDC redirect URL")
	}
	if !safeReturnPath(cfg.ReturnPath) {
		return nil, errors.New("invalid OIDC return path")
	}
	if cfg.SessionTTL <= 0 || cfg.SessionTTL > maxSessionTTL {
		return nil, errors.New("invalid OIDC session lifetime")
	}
	allowed := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, raw := range cfg.AllowedOrigins {
		u, err := parseHTTPSURL(raw)
		if err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return nil, errors.New("invalid OIDC provider origin")
		}
		allowed[urlOrigin(u)] = struct{}{}
	}
	if _, ok := allowed[urlOrigin(issuer)]; !ok {
		return nil, errors.New("OIDC issuer origin is not allowed")
	}
	var roots *x509.CertPool
	if cfg.Roots != nil {
		roots = cfg.Roots.Clone()
	}
	transport := &originTransport{allowed: allowed, base: &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: providerTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: providerTimeout,
	}}
	client := &http.Client{Transport: transport, Timeout: providerTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	discoveryCtx := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(discoveryCtx, cfg.Issuer)
	if err != nil {
		// Discovery responses are untrusted and can contain secrets or log-control
		// text. Do not return their raw body or URL to a caller.
		return nil, errors.New("OIDC discovery failed")
	}
	var metadata struct {
		JWKSURI              string   `json:"jwks_uri"`
		CodeChallengeMethods []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&metadata); err != nil || !contains(metadata.CodeChallengeMethods, "S256") {
		return nil, errors.New("OIDC provider must advertise PKCE S256")
	}
	endpoint := provider.Endpoint()
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL, metadata.JWKSURI} {
		u, err := parseHTTPSURL(raw)
		if err != nil || u.RawQuery != "" {
			return nil, errors.New("invalid OIDC provider endpoint")
		}
		if _, ok := allowed[urlOrigin(u)]; !ok {
			return nil, errors.New("OIDC provider endpoint origin is not allowed")
		}
	}
	verifier := provider.VerifierContext(discoveryCtx, &oidc.Config{
		ClientID: cfg.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256},
	})
	safeConfig := cfg
	safeConfig.ClientSecret = ""
	safeConfig.Roots = nil
	safeConfig.AllowedOrigins = nil
	return &Flow{
		config: safeConfig, appOrigin: urlOrigin(redirect), client: client, verifier: verifier,
		oauth: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
			Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID}},
		resolver: resolver, now: time.Now, pending: map[string]pendingLogin{}, sessions: map[[32]byte]session{},
	}, nil
}

func parseHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("invalid HTTPS URL")
	}
	return u, nil
}

func urlOrigin(u *url.URL) string { return "https://" + u.Host }

// RoutePaths reports only the fixed callback and post-login paths, not provider
// credentials. A host can use it to reject a mismatched route configuration.
func (f *Flow) RoutePaths() (string, string) {
	if f == nil {
		return "", ""
	}
	u, err := url.Parse(f.config.RedirectURL)
	if err != nil {
		return "", ""
	}
	return u.EscapedPath(), f.config.ReturnPath
}

func safeReturnPath(value string) bool {
	if value == "" || value[0] != '/' || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\\?#%") {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

type originTransport struct {
	allowed map[string]struct{}
	base    http.RoundTripper
}

func (t *originTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("invalid OIDC provider request")
	}
	u, err := parseHTTPSURL(req.URL.String())
	if err != nil {
		return nil, errors.New("OIDC provider request denied")
	}
	if _, ok := t.allowed[urlOrigin(u)]; !ok {
		return nil, errors.New("OIDC provider origin denied")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > maxProviderResponse {
		resp.Body.Close()
		return nil, errProviderResponseTooLarge
	}
	resp.Body = &boundedBody{ReadCloser: resp.Body, remaining: maxProviderResponse}
	return resp, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		var extra [1]byte
		n, err := b.ReadCloser.Read(extra[:])
		if n != 0 {
			return 0, errProviderResponseTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}
