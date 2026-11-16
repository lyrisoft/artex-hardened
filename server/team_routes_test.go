package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/security/oidclogin"
	"github.com/golang-jwt/jwt/v5"
)

// The entire route tree is exercised with a synthetic TLS IdP and disposable
// PostgreSQL database. No legacy router, target, model or external IdP is used.
func TestTeamHandlerOIDCAndScopedReads(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no PostgreSQL fixture: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminURL := *u
	adminURL.Path = "/postgres"
	admin, err := sql.Open("pgx", adminURL.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		admin.Close()
		t.Fatalf("PostgreSQL fixture unavailable: %v", err)
	}
	name := fmt.Sprintf("team_routes_%d", time.Now().UnixNano())
	u.Path = "/" + name
	pg, err := db.Open(u.String())
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pg.Close()
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`); err != nil {
			t.Errorf("remove synthetic database: %v", err)
		}
		_ = admin.Close()
	})
	id := func(query string, args ...any) int64 {
		t.Helper()
		var value int64
		if err := pg.QueryRow(query, args...).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pg.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, nonce, challenge string
	var idpMu sync.RWMutex
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idpMu.RLock()
		defer idpMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "fixture", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			_ = r.ParseForm()
			digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "fixture-code" || base64.RawURLEncoding.EncodeToString(digest[:]) != challenge {
				http.Error(w, "invalid fixture code", http.StatusBadRequest)
				return
			}
			now := time.Now().UTC()
			claims := jwt.MapClaims{"iss": issuer, "sub": "alice", "aud": "fixture-client", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "fixture"
			signed, err := token.SignedString(key)
			if err != nil {
				http.Error(w, "fixture signing error", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic", "token_type": "Bearer", "id_token": signed})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)
	idpMu.Lock()
	issuer = idp.URL
	idpMu.Unlock()
	tenantA := id(`INSERT INTO security_tenants(name,enabled) VALUES ('fixture-a',true) RETURNING id`)
	tenantB := id(`INSERT INTO security_tenants(name,enabled) VALUES ('fixture-b',true) RETURNING id`)
	red := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','red',true) RETURNING id`, tenantA)
	blue := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'blue','blue',true) RETURNING id`, tenantB)
	rw := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'red-workspace',true) RETURNING id`, tenantA, red)
	bw := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'blue-workspace',true) RETURNING id`, tenantB, blue)
	principal := id(`INSERT INTO security_principals(issuer,subject,kind,enabled) VALUES ($1,'alice','human',true) RETURNING id`, issuer)
	exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'viewer')`, red, principal)
	redTask, err := pg.CreateTaskWithOptions("synthetic red", "fixture", db.TaskCreateOptions{Name: "red-task"})
	if err != nil {
		t.Fatal(err)
	}
	blueTask, err := pg.CreateTaskWithOptions("synthetic blue", "fixture", db.TaskCreateOptions{Name: "blue-task"})
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2),($3,$4)`, rw, redTask.ID, bw, blueTask.ID)
	roots := x509.NewCertPool()
	roots.AddCert(idp.Certificate())
	cfg := oidclogin.Config{Issuer: issuer, ClientID: "fixture-client", ClientSecret: "synthetic-secret", RedirectURL: "https://app.example.test/team/auth/callback", AllowedOrigins: []string{issuer}, Roots: roots, ReturnPath: "/team", SessionTTL: 10 * time.Minute}
	flow, err := NewTeamOIDC(context.Background(), cfg, pg)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewTeamHandler(flow, pg)
	if err != nil {
		t.Fatal(err)
	}
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "https://app.example.test/team/auth/start", nil))
	authURL, err := url.Parse(start.Header().Get("Location"))
	if err != nil || start.Code != http.StatusFound {
		t.Fatalf("login start status=%d err=%v", start.Code, err)
	}
	idpMu.Lock()
	nonce, challenge = authURL.Query().Get("nonce"), authURL.Query().Get("code_challenge")
	idpMu.Unlock()
	var stateCookie *http.Cookie
	for _, c := range start.Result().Cookies() {
		if strings.Contains(c.Name, "oidc-state") {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("state cookie missing")
	}
	callback := httptest.NewRequest(http.MethodGet, "https://app.example.test/team/auth/callback?"+url.Values{"state": {authURL.Query().Get("state")}, "code": {"fixture-code"}}.Encode(), nil)
	callback.AddCookie(stateCookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, callback)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("callback status=%d", response.Code)
	}
	var session *http.Cookie
	for _, c := range response.Result().Cookies() {
		if strings.Contains(c.Name, "team-session") {
			session = c
		}
	}
	if session == nil {
		t.Fatal("session cookie missing")
	}
	request := func(path string, withSession bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "https://app.example.test"+path, nil)
		if withSession {
			r.AddCookie(session)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request("/team/api/workspaces", false); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", w.Code)
	}
	legacyToken, err := signJWT([]byte("synthetic-legacy-signing-key-32bytes"))
	if err != nil {
		t.Fatal(err)
	}
	legacyRequest := httptest.NewRequest(http.MethodGet, "https://app.example.test/team/api/workspaces", nil)
	legacyRequest.Header.Set("Authorization", "Bearer "+legacyToken)
	legacyReply := httptest.NewRecorder()
	handler.ServeHTTP(legacyReply, legacyRequest)
	if legacyReply.Code != http.StatusUnauthorized {
		t.Fatalf("legacy shared token accepted by team route: %d", legacyReply.Code)
	}
	if w := request("/api/tasks", true); w.Code != http.StatusNotFound {
		t.Fatalf("legacy route exposed: status=%d", w.Code)
	}
	if w := request("/team/api/workspaces", true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "red-workspace") || strings.Contains(w.Body.String(), "blue-workspace") {
		t.Fatalf("workspace filtering status=%d body=%s", w.Code, w.Body.String())
	}
	if w := request(fmt.Sprintf("/team/api/workspaces/%d/tasks", rw), true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "red-task") || strings.Contains(w.Body.String(), "blue-task") {
		t.Fatalf("task filtering status=%d body=%s", w.Code, w.Body.String())
	}
	if w := request(fmt.Sprintf("/team/api/workspaces/%d/tasks", bw), true); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "blue-task") {
		t.Fatalf("other workspace leaked status=%d body=%s", w.Code, w.Body.String())
	}
	if w := request("/team/api/workspaces?limit=1&limit=2", true); w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate pagination accepted: %d", w.Code)
	}
	writeRequest := httptest.NewRequest(http.MethodPost, fmt.Sprintf("https://app.example.test/team/api/workspaces/%d/tasks", rw), strings.NewReader(`{}`))
	writeRequest.Header.Set("Origin", "https://app.example.test")
	writeRequest.AddCookie(session)
	writeReply := httptest.NewRecorder()
	handler.ServeHTTP(writeReply, writeRequest)
	if writeReply.Code != http.StatusMethodNotAllowed {
		t.Fatalf("team read-only handler accepted a write: %d", writeReply.Code)
	}
	exec(`UPDATE security_principals SET enabled=false WHERE id=$1`, principal)
	exec(`UPDATE security_principals SET enabled=true WHERE id=$1`, principal)
	if w := request("/team/api/workspaces", true); w.Code != http.StatusUnauthorized {
		t.Fatalf("old session survived disable/re-enable: %d", w.Code)
	}
}
