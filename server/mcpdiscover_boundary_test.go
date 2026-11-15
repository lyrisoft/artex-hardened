package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

type discoveryFixtureStore struct {
	row                                               *db.MCPServer
	catalogErr, lookupErr, saveErr                    error
	catalogCalls, lookupCalls, healthCalls, saveCalls int
	saved                                             []db.MCPTool
	afterLookup                                       func()
}

func (f *discoveryFixtureStore) CheckToolCatalog(context.Context) error {
	f.catalogCalls++
	return f.catalogErr
}
func (f *discoveryFixtureStore) MCPByID(context.Context, int64) (*db.MCPServer, error) {
	f.lookupCalls++
	if f.afterLookup != nil {
		f.afterLookup()
	}
	return f.row, f.lookupErr
}
func (f *discoveryFixtureStore) UpdateMCPHealth(int64, bool, string) error {
	f.healthCalls++
	return nil
}
func (f *discoveryFixtureStore) SaveMCPTools(_ int64, items []db.MCPTool) error {
	f.saveCalls++
	f.saved = items
	return f.saveErr
}

type discoveryFixtureClient struct{ closed bool }

func (f *discoveryFixtureClient) Tools(context.Context) ([]actool.CoreTool, error) {
	return []actool.CoreTool{actool.Build(actool.Spec{Name: "synthetic_probe", Description: "local fixture"})}, nil
}
func (f *discoveryFixtureClient) Close() error { f.closed = true; return nil }

func legacyAuthenticatedTestContext(t *testing.T) context.Context {
	t.Helper()
	s := &Server{jwtKey: []byte("synthetic-test-signing-key-32bytes")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	var authenticated context.Context
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated = r.Context()
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/mcp/7/refresh", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || authenticated != nil {
		t.Fatal("unverified request was admitted")
	}
	req = httptest.NewRequest(http.MethodPost, "/api/mcp/7/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || authenticated == nil {
		t.Fatalf("authenticated request status=%d", rec.Code)
	}
	return authenticated
}

func TestStandaloneDiscoveryRequiresExplicitAuthenticatedRequest(t *testing.T) {
	auth := legacyAuthenticatedTestContext(t)
	for _, tc := range []struct {
		name                    string
		ctx                     context.Context
		row                     *db.MCPServer
		catalogErr, lookupErr   error
		requireEnabled, allowed bool
	}{
		{"background", context.Background(), &db.MCPServer{ID: 7, Enabled: true}, nil, nil, true, false},
		{"policy unavailable", auth, &db.MCPServer{ID: 7, Enabled: true}, errors.New("offline"), nil, true, false},
		{"lookup unavailable", auth, nil, nil, errors.New("offline"), true, false},
		{"deleted", auth, nil, nil, nil, true, false},
		{"wrong row", auth, &db.MCPServer{ID: 8, Enabled: true}, nil, nil, true, false},
		{"disabled after save", auth, &db.MCPServer{ID: 7, Enabled: false}, nil, nil, true, false},
		{"enabled saved row", auth, &db.MCPServer{ID: 7, Enabled: true, Name: "current"}, nil, nil, true, true},
		{"explicit disabled refresh", auth, &db.MCPServer{ID: 7, Enabled: false, Name: "current"}, nil, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &discoveryFixtureStore{row: tc.row, catalogErr: tc.catalogErr, lookupErr: tc.lookupErr}
			client := &discoveryFixtureClient{}
			connects := 0
			err := discoverMCP(tc.ctx, store, 7, tc.requireEnabled, func(_ context.Context, m *db.MCPServer) (mcpClient, error) {
				connects++
				if m != tc.row {
					t.Fatal("used stale or unexpected MCP configuration")
				}
				return client, nil
			})
			if tc.allowed {
				if err != nil || connects != 1 || !client.closed || store.saveCalls != 1 || !reflect.DeepEqual(store.saved, []db.MCPTool{{Name: "synthetic_probe", Description: "local fixture"}}) {
					t.Fatalf("allowed discovery: err=%v connects=%d closed=%v saved=%v", err, connects, client.closed, store.saved)
				}
			} else if err == nil || connects != 0 || store.saveCalls != 0 {
				t.Fatalf("denied discovery: err=%v connects=%d saves=%d", err, connects, store.saveCalls)
			}
			if tc.name == "background" && (store.catalogCalls != 0 || store.lookupCalls != 0) {
				t.Fatal("background discovery accessed the policy store")
			}
			if tc.name == "policy unavailable" && store.lookupCalls != 0 {
				t.Fatal("decrypted MCP configuration after policy failure")
			}
		})
	}
	ctx, cancel := context.WithCancel(auth)
	store := &discoveryFixtureStore{row: &db.MCPServer{ID: 7, Enabled: true}, afterLookup: cancel}
	connects := 0
	err := discoverMCP(ctx, store, 7, true, func(context.Context, *db.MCPServer) (mcpClient, error) {
		connects++
		return &discoveryFixtureClient{}, nil
	})
	if !errors.Is(err, context.Canceled) || connects != 0 {
		t.Fatalf("cancelled discovery: err=%v connects=%d", err, connects)
	}
}
