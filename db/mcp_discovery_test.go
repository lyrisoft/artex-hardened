package db

import (
	"context"
	"strings"
	"testing"
)

func TestMCPByIDReadsOnlyRequestedConfiguration(t *testing.T) {
	d, err := Open(scratchDSN(t, "mcp_discovery"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var id int64
	err = d.QueryRow(`INSERT INTO mcp_servers(name,transport,url,env,enabled) VALUES ('fixture-discovery','http','http://127.0.0.1:1','{"X-API-Key":"synthetic-only"}'::jsonb,true) RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CheckToolCatalog(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, err := d.MCPByID(context.Background(), id)
	if err != nil || m == nil || m.ID != id || !m.Enabled || !strings.Contains(string(m.Env), "synthetic-only") {
		t.Fatalf("selected MCP=%+v err=%v", m, err)
	}
	m, err = d.MCPByID(context.Background(), id+999999)
	if err != nil || m != nil {
		t.Fatalf("missing MCP=%+v err=%v", m, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.MCPByID(ctx, id); err == nil {
		t.Fatal("cancelled MCP lookup succeeded")
	}
	if err := d.CheckToolCatalog(ctx); err == nil {
		t.Fatal("cancelled catalog check succeeded")
	}
}
