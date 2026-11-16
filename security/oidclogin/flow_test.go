package oidclogin

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type fixtureResolver struct {
	mu      sync.Mutex
	issuer  string
	enabled bool
	id      int64
	epoch   int64
	calls   int
}

func (r *fixtureResolver) ResolveHuman(_ context.Context, issuer, subject string) (Human, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if !r.enabled || issuer != r.issuer || subject != "alice" {
		return Human{}, errors.New("unknown fixture principal")
	}
	return Human{ID: r.id, AuthEpoch: r.epoch}, nil
}

func (r *fixtureResolver) disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = false
	r.epoch++
}

type fakeProvider struct {
	server             *httptest.Server
	key, wrongKey      *rsa.PrivateKey
	mu                 sync.Mutex
	nonce, challenge   string
	mutate             func(jwt.MapClaims)
	wrongSignature     bool
	duplicateClaim     bool
	lastIDToken        string
	tokenCalls         int
	lastVerifier       string
	metadataJWKS       string
	metadataPKCEMethod []string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{key: key, wrongKey: wrong, metadataPKCEMethod: []string{"S256"}}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakeProvider) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		jwks := p.metadataJWKS
		if jwks == "" {
			jwks = p.server.URL + "/jwks"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize",
			"token_endpoint": p.server.URL + "/token", "jwks_uri": jwks,
			"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": p.metadataPKCEMethod,
		})
	case "/jwks":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "fixture-key", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.PublicKey.E)).Bytes()),
		}}})
	case "/token":
		p.tokenCalls++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid fixture form", http.StatusBadRequest)
			return
		}
		p.lastVerifier = r.Form.Get("code_verifier")
		digest := sha256.Sum256([]byte(p.lastVerifier))
		clientID, secret, basic := r.BasicAuth()
		if !basic {
			clientID, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		if r.Method != http.MethodPost || clientID != "fixture-client" || secret != "synthetic-secret" || r.Form.Get("redirect_uri") != "https://app.example.test/team/auth/callback" || r.Form.Get("code") != "fixture-code" || p.lastVerifier == "" || base64.RawURLEncoding.EncodeToString(digest[:]) != p.challenge {
			http.Error(w, "invalid fixture code", http.StatusBadRequest)
			return
		}
		now := time.Now().UTC()
		claims := jwt.MapClaims{"iss": p.server.URL, "sub": "alice", "aud": "fixture-client", "azp": "fixture-client", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": p.nonce}
		if p.mutate != nil {
			p.mutate(claims)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "fixture-key"
		key := p.key
		if p.wrongSignature {
			key = p.wrongKey
		}
		signed, err := token.SignedString(key)
		if err != nil {
			http.Error(w, "fixture signing failed", http.StatusInternalServerError)
			return
		}
		if p.duplicateClaim {
			payload, err := json.Marshal(claims)
			if err != nil {
				http.Error(w, "fixture claims error", http.StatusInternalServerError)
				return
			}
			payloadText := strings.Replace(string(payload), `"sub":"alice"`, `"sub":"other","sub":"alice"`, 1)
			if payloadText == string(payload) {
				http.Error(w, "fixture subject missing", http.StatusInternalServerError)
				return
			}
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture-key"}`))
			body := base64.RawURLEncoding.EncodeToString([]byte(payloadText))
			message := header + "." + body
			digest := sha256.Sum256([]byte(message))
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			if err != nil {
				http.Error(w, "fixture signing failed", http.StatusInternalServerError)
				return
			}
			signed = message + "." + base64.RawURLEncoding.EncodeToString(signature)
		}
		p.lastIDToken = signed
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access-token", "token_type": "Bearer", "id_token": signed})
	default:
		http.NotFound(w, r)
	}
}

func (p *fakeProvider) configure(nonce, challenge string, mutate func(jwt.MapClaims), wrongSignature bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nonce, p.challenge, p.mutate, p.wrongSignature = nonce, challenge, mutate, wrongSignature
	p.duplicateClaim = false
}

func newFixtureFlow(t *testing.T, p *fakeProvider) (*Flow, *fixtureResolver, Config) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(p.server.Certificate())
	resolver := &fixtureResolver{issuer: p.server.URL, enabled: true, id: 41, epoch: 1}
	cfg := Config{Issuer: p.server.URL, ClientID: "fixture-client", ClientSecret: "synthetic-secret", RedirectURL: "https://app.example.test/team/auth/callback", AllowedOrigins: []string{p.server.URL}, Roots: roots, ReturnPath: "/team", SessionTTL: 10 * time.Minute}
	flow, err := New(context.Background(), cfg, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return flow, resolver, cfg
}

type startedLogin struct {
	state, nonce, challenge string
	cookie                  *http.Cookie
}

func startFixtureLogin(t *testing.T, flow *Flow) startedLogin {
	t.Helper()
	w := httptest.NewRecorder()
	flow.Start(w, httptest.NewRequest(http.MethodGet, "https://app.example.test/team/auth/start", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("start status=%d", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "fixture-client" || q.Get("redirect_uri") != "https://app.example.test/team/auth/callback" {
		t.Fatal("authorization request omitted required bindings")
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == stateCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode || cookie.Value != q.Get("state") {
		t.Fatal("state cookie is missing or not bound to the browser")
	}
	return startedLogin{state: q.Get("state"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), cookie: cookie}
}

func finishFixtureLogin(flow *Flow, login startedLogin) *httptest.ResponseRecorder {
	q := url.Values{"state": {login.state}, "code": {"fixture-code"}}
	r := httptest.NewRequest(http.MethodGet, "https://app.example.test/team/auth/callback?"+q.Encode(), nil)
	r.AddCookie(login.cookie)
	w := httptest.NewRecorder()
	flow.Callback(w, r)
	return w
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestHumanLoginUsesOneTimePKCEAndRechecksPrincipal(t *testing.T) {
	p := newFakeProvider(t)
	flow, resolver, cfg := newFixtureFlow(t, p)
	login := startFixtureLogin(t, flow)
	p.configure(login.nonce, login.challenge, nil, false)
	w := finishFixtureLogin(flow, login)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/team" {
		t.Fatalf("callback status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	cookie := cookieNamed(w, sessionCookie)
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.Value == "" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("session cookie missing or unsafe")
	}
	if again := finishFixtureLogin(flow, login); again.Code != http.StatusUnauthorized {
		t.Fatalf("replayed callback status=%d", again.Code)
	}
	protected := flow.RequireHuman(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		human, ok := HumanFromContext(r.Context())
		if !ok || human.ID != 41 || human.AuthEpoch <= 0 {
			t.Errorf("principal=%+v ok=%v", human, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(method, origin string, cookies ...*http.Cookie) int {
		t.Helper()
		r := httptest.NewRequest(method, "https://app.example.test/team/resource", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		return w.Code
	}
	if got := call(http.MethodGet, ""); got != http.StatusUnauthorized {
		t.Fatalf("missing session status=%d", got)
	}
	if got := call(http.MethodGet, "", cookie); got != http.StatusNoContent {
		t.Fatalf("valid session status=%d", got)
	}
	if got := call(http.MethodPost, "https://attacker.invalid", cookie); got != http.StatusUnauthorized {
		t.Fatalf("cross-origin write status=%d", got)
	}
	if got := call(http.MethodPost, "", cookie); got != http.StatusUnauthorized {
		t.Fatalf("missing-origin write status=%d", got)
	}
	if got := call(http.MethodPost, "https://app.example.test", cookie); got != http.StatusNoContent {
		t.Fatalf("same-origin write status=%d", got)
	}
	if got := call(http.MethodGet, "", cookie, cookie); got != http.StatusUnauthorized {
		t.Fatalf("duplicate session cookie status=%d", got)
	}
	resolver.disable()
	if got := call(http.MethodGet, "", cookie); got != http.StatusUnauthorized {
		t.Fatalf("disabled principal status=%d", got)
	}
	resolver.mu.Lock()
	resolver.enabled = true
	resolver.mu.Unlock()
	if got := call(http.MethodGet, "", cookie); got != http.StatusUnauthorized {
		t.Fatalf("disabled session revived status=%d", got)
	}
	// A disable/re-enable between requests must also invalidate the old session.
	second := startFixtureLogin(t, flow)
	p.configure(second.nonce, second.challenge, nil, false)
	secondReply := finishFixtureLogin(flow, second)
	secondCookie := cookieNamed(secondReply, sessionCookie)
	if secondReply.Code != http.StatusSeeOther || secondCookie == nil {
		t.Fatal("could not establish second fixture session")
	}
	resolver.disable()
	resolver.mu.Lock()
	resolver.enabled = true
	resolver.mu.Unlock()
	if got := call(http.MethodGet, "", secondCookie); got != http.StatusUnauthorized {
		t.Fatalf("session survived a disable/re-enable cycle: %d", got)
	}
	if cfg.SessionTTL > maxSessionTTL {
		t.Fatal("fixture violates session lifetime")
	}
}

func TestCallbackRejectsInvalidVerifiedClaims(t *testing.T) {
	p := newFakeProvider(t)
	flow, _, _ := newFixtureFlow(t, p)
	for _, tc := range []struct {
		name   string
		mutate func(jwt.MapClaims)
		wrong  bool
	}{
		{"nonce", func(c jwt.MapClaims) { c["nonce"] = "wrong" }, false},
		{"issuer", func(c jwt.MapClaims) { c["iss"] = "https://other.invalid" }, false},
		{"audience", func(c jwt.MapClaims) { c["aud"] = "other-client" }, false},
		{"multiple audiences", func(c jwt.MapClaims) { c["aud"] = []string{"fixture-client", "other"} }, false},
		{"authorized party", func(c jwt.MapClaims) { c["azp"] = "other-client" }, false},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, false},
		{"future issuance", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(2 * time.Minute).Unix() }, false},
		{"old issuance", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(-10 * time.Minute).Unix() }, false},
		{"empty subject", func(c jwt.MapClaims) { c["sub"] = "" }, false},
		{"non-ascii subject", func(c jwt.MapClaims) { c["sub"] = "☃" }, false},
		{"signature", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			login := startFixtureLogin(t, flow)
			p.configure(login.nonce, login.challenge, tc.mutate, tc.wrong)
			w := finishFixtureLogin(flow, login)
			if w.Code != http.StatusUnauthorized || cookieNamed(w, sessionCookie) != nil {
				t.Fatalf("invalid claim accepted: status=%d", w.Code)
			}
		})
	}
}

func TestLoginRejectsStateErrorsBeforeTokenExchange(t *testing.T) {
	p := newFakeProvider(t)
	flow, _, _ := newFixtureFlow(t, p)
	login := startFixtureLogin(t, flow)
	p.configure(login.nonce, login.challenge, nil, false)
	for _, query := range []string{
		"state=" + url.QueryEscape(login.state) + "&code=fixture-code&code=second",
		"state=" + url.QueryEscape(login.state) + "&state=second&code=fixture-code",
		"state=wrong&code=fixture-code",
		"state=" + url.QueryEscape(login.state) + "&code=fixture-code&iss=https%3A%2F%2Fother.invalid",
	} {
		r := httptest.NewRequest(http.MethodGet, "https://app.example.test/team/auth/callback?"+query, nil)
		r.AddCookie(login.cookie)
		w := httptest.NewRecorder()
		flow.Callback(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("invalid callback status=%d", w.Code)
		}
	}
	p.mu.Lock()
	calls := p.tokenCalls
	p.mu.Unlock()
	if calls != 0 {
		t.Fatal("invalid state reached token endpoint")
	}
	if w := finishFixtureLogin(flow, login); w.Code != http.StatusSeeOther {
		t.Fatalf("valid callback after invalid attempts: %d", w.Code)
	}
}

func TestCallbackRejectsSignedDuplicateClaim(t *testing.T) {
	p := newFakeProvider(t)
	flow, _, _ := newFixtureFlow(t, p)
	login := startFixtureLogin(t, flow)
	p.configure(login.nonce, login.challenge, nil, false)
	p.mu.Lock()
	p.duplicateClaim = true
	p.mu.Unlock()
	w := finishFixtureLogin(flow, login)
	if w.Code != http.StatusUnauthorized || cookieNamed(w, sessionCookie) != nil {
		t.Fatalf("ambiguous signed claims accepted: %d", w.Code)
	}
	p.mu.Lock()
	raw := p.lastIDToken
	p.mu.Unlock()
	parsed, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return &p.key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("fixture was not correctly signed: %v", err)
	}
}

func TestCompactTokenRejectsAmbiguousJSON(t *testing.T) {
	encode := base64.RawURLEncoding.EncodeToString
	for _, tc := range []struct {
		name, header, claims string
		valid                bool
	}{
		{"well formed", `{"alg":"RS256"}`, `{"sub":"alice"}`, true},
		{"duplicate header", `{"alg":"RS256","alg":"none"}`, `{"sub":"alice"}`, false},
		{"escaped duplicate", `{"alg":"RS256"}`, `{"sub":"alice","\u0073ub":"other"}`, false},
		{"case-variant claim", `{"alg":"RS256"}`, `{"sub":"alice","SUB":"other"}`, false},
		{"case-variant header", `{"alg":"RS256","ALG":"none"}`, `{"sub":"alice"}`, false},
		{"invalid unicode", `{"alg":"RS256"}`, `{"sub":"\ud800"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := encode([]byte(tc.header)) + "." + encode([]byte(tc.claims)) + "." + encode([]byte("signature"))
			if got := validCompactIDToken(raw); got != tc.valid {
				t.Fatalf("valid=%v want %v", got, tc.valid)
			}
		})
	}
}

func TestConcurrentCallbackConsumesStateOnce(t *testing.T) {
	p := newFakeProvider(t)
	flow, _, _ := newFixtureFlow(t, p)
	login := startFixtureLogin(t, flow)
	p.configure(login.nonce, login.challenge, nil, false)
	const attempts = 8
	statuses := make(chan int, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- finishFixtureLogin(flow, login).Code
		}()
	}
	wg.Wait()
	close(statuses)
	success := 0
	for status := range statuses {
		if status == http.StatusSeeOther {
			success++
		} else if status != http.StatusUnauthorized {
			t.Fatalf("unexpected callback status=%d", status)
		}
	}
	p.mu.Lock()
	calls := p.tokenCalls
	p.mu.Unlock()
	if success != 1 || calls != 1 {
		t.Fatalf("callback successes=%d token calls=%d", success, calls)
	}
}

func TestExpiredStateAndLogout(t *testing.T) {
	p := newFakeProvider(t)
	flow, _, _ := newFixtureFlow(t, p)
	base := time.Now()
	flow.now = func() time.Time { return base }
	expired := startFixtureLogin(t, flow)
	p.configure(expired.nonce, expired.challenge, nil, false)
	flow.now = func() time.Time { return base.Add(pendingTTL) }
	if w := finishFixtureLogin(flow, expired); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired state status=%d", w.Code)
	}
	p.mu.Lock()
	calls := p.tokenCalls
	p.mu.Unlock()
	if calls != 0 {
		t.Fatal("expired state reached token endpoint")
	}
	flow.now = time.Now
	login := startFixtureLogin(t, flow)
	p.configure(login.nonce, login.challenge, nil, false)
	w := finishFixtureLogin(flow, login)
	cookie := cookieNamed(w, sessionCookie)
	if w.Code != http.StatusSeeOther || cookie == nil {
		t.Fatal("fixture session not created")
	}
	logout := func(origin string) int {
		r := httptest.NewRequest(http.MethodPost, "https://app.example.test/team/auth/logout", nil)
		r.Header.Set("Origin", origin)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		flow.Logout(w, r)
		return w.Code
	}
	if got := logout("https://attacker.invalid"); got != http.StatusUnauthorized {
		t.Fatalf("cross-origin logout status=%d", got)
	}
	if got := logout("https://app.example.test"); got != http.StatusNoContent {
		t.Fatalf("logout status=%d", got)
	}
	protected := flow.RequireHuman(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest(http.MethodGet, "https://app.example.test/team/resource", nil)
	r.AddCookie(cookie)
	result := httptest.NewRecorder()
	protected.ServeHTTP(result, r)
	if result.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out session status=%d", result.Code)
	}
	third := startFixtureLogin(t, flow)
	p.configure(third.nonce, third.challenge, nil, false)
	thirdReply := finishFixtureLogin(flow, third)
	thirdCookie := cookieNamed(thirdReply, sessionCookie)
	if thirdReply.Code != http.StatusSeeOther || thirdCookie == nil {
		t.Fatal("could not establish expiry fixture session")
	}
	flow.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	expiredRequest := httptest.NewRequest(http.MethodGet, "https://app.example.test/team/resource", nil)
	expiredRequest.AddCookie(thirdCookie)
	expiredReply := httptest.NewRecorder()
	protected.ServeHTTP(expiredReply, expiredRequest)
	if expiredReply.Code != http.StatusUnauthorized {
		t.Fatalf("expired session status=%d", expiredReply.Code)
	}
}

type fixtureRoundTripper func(*http.Request) (*http.Response, error)

func (f fixtureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProviderTransportEnforcesOriginAndResponseLimit(t *testing.T) {
	calls := 0
	transport := &originTransport{allowed: map[string]struct{}{"https://idp.example.test": {}}, base: fixtureRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxProviderResponse+1)))}, nil
	})}
	if _, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://other.invalid/jwks", nil)); err == nil || calls != 0 {
		t.Fatal("unapproved origin reached transport")
	}
	response, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://idp.example.test/jwks", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); !errors.Is(err, errProviderResponseTooLarge) {
		t.Fatalf("oversized response error=%v", err)
	}
}

func TestProviderConfigurationFailsClosed(t *testing.T) {
	p := newFakeProvider(t)
	_, resolver, valid := newFixtureFlow(t, p)
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"http issuer", func(c *Config) { c.Issuer = strings.Replace(c.Issuer, "https://", "http://", 1) }},
		{"http redirect", func(c *Config) { c.RedirectURL = "http://app.example.test/callback" }},
		{"missing origin", func(c *Config) { c.AllowedOrigins = nil }},
		{"open return", func(c *Config) { c.ReturnPath = "//attacker.invalid" }},
		{"encoded return", func(c *Config) { c.ReturnPath = "/%2fattacker.invalid" }},
		{"long session", func(c *Config) { c.SessionTTL = time.Hour }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.change(&cfg)
			if _, err := New(context.Background(), cfg, resolver); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	p.mu.Lock()
	p.metadataJWKS = "https://attacker.invalid/jwks"
	p.mu.Unlock()
	if _, err := New(context.Background(), valid, resolver); err == nil {
		t.Fatal("unapproved JWKS origin accepted")
	}
	p.mu.Lock()
	p.metadataJWKS = ""
	p.metadataPKCEMethod = []string{"plain"}
	p.mu.Unlock()
	if _, err := New(context.Background(), valid, resolver); err == nil {
		t.Fatal("provider without S256 accepted")
	}
}
