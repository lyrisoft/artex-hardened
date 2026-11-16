package oidclogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/security/strictjson"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	stateCookie   = "__Host-artex-oidc-state"
	sessionCookie = "__Host-artex-team-session"
	pendingTTL    = 5 * time.Minute
	maxSessionTTL = 30 * time.Minute
	maxEntries    = 1024
	maxTokenBytes = 32768
)

// Flow holds only short-lived login transactions and opaque in-memory sessions.
// Restart invalidates them. Neither an ID token nor an access token is stored.
// A verified identity alone grants no task, workspace, tool or evidence access.
type Flow struct {
	config    Config
	appOrigin string
	client    *http.Client
	verifier  *oidc.IDTokenVerifier
	oauth     oauth2.Config
	resolver  HumanResolver
	now       func() time.Time
	mu        sync.Mutex
	pending   map[string]pendingLogin
	sessions  map[[32]byte]session
}

type pendingLogin struct {
	nonce, verifier string
	created         time.Time
}

type session struct {
	principalID, authEpoch int64
	issuer, subject        string
	expires                time.Time
}

type principalContextKey struct{}

// HumanFromContext returns the verified ID and revocation generation installed
// by RequireHuman. Resource queries must compare both to the database in the
// same statement as authorization; a prior authentication check is not a lease.
func HumanFromContext(ctx context.Context) (Human, bool) {
	if ctx == nil {
		return Human{}, false
	}
	human, ok := ctx.Value(principalContextKey{}).(Human)
	return human, ok && human.ID > 0 && human.AuthEpoch > 0
}

// Start begins a one-time authorization-code flow with S256 PKCE and a nonce.
// The returned state is bound to a Secure, HttpOnly, host-only browser cookie.
func (f *Flow) Start(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := randomToken()
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	verifier, err := randomToken()
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	now := f.now()
	f.mu.Lock()
	f.pruneLocked(now)
	if len(f.pending) >= maxEntries {
		f.mu.Unlock()
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	f.pending[state] = pendingLogin{nonce: nonce, verifier: verifier, created: now}
	f.mu.Unlock()
	setCookie(w, stateCookie, state, int(pendingTTL.Seconds()), now.Add(pendingTTL))
	target := f.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, target, http.StatusFound)
}

// Callback consumes state before exchanging a code. It validates signature,
// issuer, audience, authorized party, expiry, issuance time and the login nonce,
// then resolves an already-provisioned human. No account is auto-created.
func (f *Flow) Callback(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stateCookieValue, ok := oneCookie(r, stateCookie)
	clearCookie(w, stateCookie)
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !ok || len(query["state"]) != 1 || len(query["code"]) != 1 || len(query["error"]) != 0 || len(query["iss"]) > 1 {
		authFailed(w)
		return
	}
	state, code := query.Get("state"), query.Get("code")
	if len(state) != 43 || len(code) == 0 || len(code) > 4096 || subtle.ConstantTimeCompare([]byte(state), []byte(stateCookieValue)) != 1 || (len(query["iss"]) == 1 && query.Get("iss") != f.config.Issuer) {
		authFailed(w)
		return
	}
	now := f.now()
	f.mu.Lock()
	pending, exists := f.pending[state]
	delete(f.pending, state)
	f.mu.Unlock()
	if !exists || now.Before(pending.created) || !now.Before(pending.created.Add(pendingTTL)) {
		authFailed(w)
		return
	}
	ctx := oidc.ClientContext(r.Context(), f.client)
	token, err := f.oauth.Exchange(ctx, code, oauth2.VerifierOption(pending.verifier))
	if err != nil {
		authFailed(w)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || !validCompactIDToken(raw) {
		authFailed(w)
		return
	}
	verified, err := f.verifier.Verify(ctx, raw)
	if err != nil || verified.Issuer != f.config.Issuer || len(verified.Audience) != 1 || verified.Audience[0] != f.config.ClientID || !validSubject(verified.Subject) || subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(pending.nonce)) != 1 || verified.IssuedAt.IsZero() || verified.IssuedAt.Before(pending.created.Add(-time.Minute)) || verified.IssuedAt.After(now.Add(time.Minute)) || !verified.Expiry.After(now) {
		authFailed(w)
		return
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := verified.Claims(&claims); err != nil || (claims.AuthorizedParty != "" && claims.AuthorizedParty != f.config.ClientID) {
		authFailed(w)
		return
	}
	human, err := f.resolver.ResolveHuman(r.Context(), verified.Issuer, verified.Subject)
	if err != nil || human.ID <= 0 || human.AuthEpoch <= 0 {
		authFailed(w)
		return
	}
	sessionToken, err := randomToken()
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	expires := now.Add(f.config.SessionTTL)
	if verified.Expiry.Before(expires) {
		expires = verified.Expiry
	}
	key := sha256.Sum256([]byte(sessionToken))
	f.mu.Lock()
	f.pruneLocked(now)
	if len(f.sessions) >= maxEntries {
		f.mu.Unlock()
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	f.sessions[key] = session{principalID: human.ID, authEpoch: human.AuthEpoch, issuer: verified.Issuer, subject: verified.Subject, expires: expires}
	f.mu.Unlock()
	setCookie(w, sessionCookie, sessionToken, int(expires.Sub(now).Seconds()), expires)
	http.Redirect(w, r, f.config.ReturnPath, http.StatusSeeOther)
}

// RequireHuman authenticates the opaque session and rechecks the persisted
// principal on every request. Unsafe methods also require an exact Origin. Do
// not wrap the legacy router: its routes do not enforce workspace authorization.
func (f *Flow) RequireHuman(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		if next == nil || (!safeMethod(r.Method) && !f.sameOrigin(r)) {
			authFailed(w)
			return
		}
		value, ok := oneCookie(r, sessionCookie)
		if !ok || len(value) != 43 {
			authFailed(w)
			return
		}
		key := sha256.Sum256([]byte(value))
		now := f.now()
		f.mu.Lock()
		s, exists := f.sessions[key]
		if exists && !now.Before(s.expires) {
			delete(f.sessions, key)
			exists = false
		}
		f.mu.Unlock()
		if !exists {
			authFailed(w)
			return
		}
		human, err := f.resolver.ResolveHuman(r.Context(), s.issuer, s.subject)
		if err != nil || human.ID != s.principalID || human.AuthEpoch != s.authEpoch {
			f.mu.Lock()
			delete(f.sessions, key)
			f.mu.Unlock()
			authFailed(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, human)))
	})
}

// Logout removes the server-side session. It requires POST and the exact app
// Origin, so a cross-site page cannot silently end another person's session.
func (f *Flow) Logout(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !f.sameOrigin(r) {
		authFailed(w)
		return
	}
	if value, ok := oneCookie(r, sessionCookie); ok {
		key := sha256.Sum256([]byte(value))
		f.mu.Lock()
		delete(f.sessions, key)
		f.mu.Unlock()
	}
	clearCookie(w, sessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

func (f *Flow) pruneLocked(now time.Time) {
	for key, item := range f.pending {
		if !now.Before(item.created.Add(pendingTTL)) {
			delete(f.pending, key)
		}
	}
	for key, item := range f.sessions {
		if !now.Before(item.expires) {
			delete(f.sessions, key)
		}
	}
}

func randomToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func oneCookie(r *http.Request, name string) (string, bool) {
	var value string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			value = c.Value
			count++
		}
	}
	return value, count == 1 && value != ""
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Expires: expires})
}

func clearCookie(w http.ResponseWriter, name string) {
	setCookie(w, name, "", -1, time.Unix(1, 0).UTC())
}

func safeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func authFailed(w http.ResponseWriter) {
	http.Error(w, "authentication failed", http.StatusUnauthorized)
}

func (f *Flow) sameOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	return len(origins) == 1 && origins[0] == f.appOrigin
}

// OIDC subjects are ASCII identifiers of at most 255 characters. Disallow
// control characters so their storage and audit representation is clear.
func validSubject(subject string) bool {
	if len(subject) == 0 || len(subject) > 255 {
		return false
	}
	for _, c := range []byte(subject) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// Reject ambiguous JSON before handing a compact token to the maintained OIDC
// verifier. These unverified bytes can only cause denial, never authentication.
func validCompactIDToken(raw string) bool {
	if len(raw) == 0 || len(raw) > maxTokenBytes {
		return false
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[2] == "" {
		return false
	}
	encoding := base64.RawURLEncoding.Strict()
	header, err := encoding.DecodeString(parts[0])
	if err != nil || !strictjson.ValidObject(header, 4096, 16) || !canonicalKeys(header, []string{"alg", "kid", "typ", "cty", "crit", "jku", "jwk", "x5u", "x5c", "b64"}) {
		return false
	}
	claims, err := encoding.DecodeString(parts[1])
	if err != nil || !strictjson.ValidObject(claims, maxTokenBytes, 32) || !canonicalKeys(claims, []string{"iss", "sub", "aud", "exp", "iat", "nbf", "nonce", "azp", "auth_time", "at_hash", "c_hash", "_claim_names", "_claim_sources"}) {
		return false
	}
	_, err = encoding.DecodeString(parts[2])
	return err == nil
}

// encoding/json matches struct fields case-insensitively. Reject lookalike
// standard fields so another parser cannot interpret the same token differently.
func canonicalKeys(document []byte, reserved []string) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil {
		return false
	}
	for key := range object {
		for _, name := range reserved {
			if key != name && strings.EqualFold(key, name) {
				return false
			}
		}
	}
	return true
}
