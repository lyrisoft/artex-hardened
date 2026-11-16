package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func newSyntheticMCPServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	hits := &atomic.Int64{}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var rpc struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&rpc); err != nil {
			t.Errorf("decode fixture request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch rpc.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`, rpc.ID)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"synthetic_probe","description":"fixture","inputSchema":{"type":"object"}}]}}`, rpc.ID)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.Close)
	return fake, hits
}

// Exercise the real authenticated HTTP route against a loopback-only MCP. An
// explicitly requested refresh remains usable for disabled legacy entries.
func TestMCPDiscoveryHTTPPreservesExplicitRefresh(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	fake, hits := newSyntheticMCPServer(t)
	body, _ := json.Marshal(map[string]any{"name": "fixture-explicit-discovery", "transport": "http", "url": fake.URL, "enabled": true, "args": []any{}, "env": map[string]string{}})
	created := request(http.MethodPost, "/api/mcp", string(body))
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body)
	}
	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || result.ID <= 0 {
		t.Fatalf("create result=%+v err=%v", result, err)
	}
	t.Cleanup(func() {
		if err := s.m.pg.DeleteMCP(result.ID); err != nil {
			t.Errorf("remove fixture: %v", err)
		}
	})
	if hits.Load() == 0 {
		t.Fatal("explicit enabled creation did not discover")
	}
	cached, err := s.m.pg.MCPToolsDetailed(result.ID)
	if err != nil || len(cached) != 1 || !strings.Contains(cached[0].Name, "synthetic_probe") {
		t.Fatalf("cached tools=%+v err=%v", cached, err)
	}
	if _, err := s.m.pg.Exec(`UPDATE mcp_servers SET enabled=false WHERE id=$1`, result.ID); err != nil {
		t.Fatal(err)
	}
	path := "/api/mcp/" + strconv.FormatInt(result.ID, 10) + "/refresh"
	before := hits.Load()
	unauth := httptest.NewRecorder()
	s.Handler().ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, path, nil))
	if unauth.Code != http.StatusUnauthorized || hits.Load() != before {
		t.Fatalf("unauthenticated refresh status=%d hits=%d", unauth.Code, hits.Load()-before)
	}
	refreshed := request(http.MethodPost, path, "")
	if refreshed.Code != http.StatusOK || hits.Load() <= before {
		t.Fatalf("explicit disabled refresh status=%d body=%s hits=%d", refreshed.Code, refreshed.Body, hits.Load()-before)
	}
}
