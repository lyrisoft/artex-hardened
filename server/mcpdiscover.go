package server

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcphttp"
	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
)

// legacyMCPRequestKey marks a request authenticated by the existing shared JWT.
// It is not a unique human identity, team membership, or target approval.
type legacyMCPRequestKey struct{}

var errMCPDiscoveryDenied = errors.New("standalone MCP discovery unavailable")

// mcpClient is the shared surface of a connected MCP server (stdio, Streamable
// HTTP or legacy SSE), so tools/list and cleanup are handled uniformly.
type mcpClient interface {
	Tools(context.Context) ([]actool.CoreTool, error)
	Close() error
}

// connectMCP dials one MCP server per its transport. Callers must Close the client.
func connectMCP(ctx context.Context, m *db.MCPServer) (mcpClient, error) {
	switch m.Transport {
	case "stdio":
		if m.Command == "" {
			return nil, fmt.Errorf("stdio transport is missing a command")
		}
		return mcp.NewStdioClient(ctx, m.Name, m.Command, jsonStrMap(m.Env), jsonStrSlice(m.Args)...)
	case "http":
		if m.URL == "" {
			return nil, fmt.Errorf("http transport is missing a URL")
		}
		return mcphttp.New(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure, m.TimeoutSeconds)
	case "sse":
		if m.URL == "" {
			return nil, fmt.Errorf("sse transport is missing a URL")
		}
		return mcphttp.NewSSE(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure)
	default:
		return nil, fmt.Errorf("unknown transport %q", m.Transport)
	}
}

type mcpDiscoveryStore interface {
	CheckToolCatalog(context.Context) error
	MCPByID(context.Context, int64) (*db.MCPServer, error)
	UpdateMCPHealth(int64, bool, string) error
	SaveMCPTools(int64, []db.MCPTool) error
}

// resolveMCPForDiscovery requires an explicit legacy-authenticated HTTP request,
// checks catalog availability and reloads exactly the named MCP configuration.
// The shared JWT and catalog check are not team authorization or isolation.
// Future scoped principals need a separate action-specific authorization gate.
func resolveMCPForDiscovery(ctx context.Context, store mcpDiscoveryStore, id int64, requireEnabled bool) (*db.MCPServer, error) {
	if ctx == nil || store == nil || id <= 0 {
		return nil, errMCPDiscoveryDenied
	}
	if ok, _ := ctx.Value(legacyMCPRequestKey{}).(bool); !ok {
		return nil, errMCPDiscoveryDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := store.CheckToolCatalog(ctx); err != nil {
		return nil, fmt.Errorf("MCP discovery catalog unavailable: %w", err)
	}
	m, err := store.MCPByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("load MCP for discovery: %w", err)
	}
	if m == nil || m.ID != id || (requireEnabled && !m.Enabled) {
		return nil, errMCPDiscoveryDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

// discoverMCP connects only after resolveMCPForDiscovery succeeds. Enabled-on-save
// discovery rechecks enabled; explicit refresh of a disabled legacy MCP remains
// supported. A later configuration change cannot yet interrupt an active client.
func discoverMCP(ctx context.Context, store mcpDiscoveryStore, id int64, requireEnabled bool, connect func(context.Context, *db.MCPServer) (mcpClient, error)) error {
	if connect == nil {
		return errMCPDiscoveryDenied
	}
	m, err := resolveMCPForDiscovery(ctx, store, id, requireEnabled)
	if err != nil {
		return err
	}
	cl, err := connect(ctx, m)
	if err != nil {
		_ = store.UpdateMCPHealth(id, false, err.Error())
		return err
	}
	defer cl.Close()
	ts, err := cl.Tools(ctx)
	if err != nil {
		_ = store.UpdateMCPHealth(id, false, err.Error())
		return err
	}
	_ = store.UpdateMCPHealth(id, true, "")
	tools := make([]db.MCPTool, 0, len(ts))
	for _, t := range ts {
		tools = append(tools, db.MCPTool{Name: t.Name(), Description: t.Description()})
	}
	if err := store.SaveMCPTools(id, tools); err != nil {
		return err
	}
	log.Printf("[mcp] %s discovered %d tools and cached them", m.Name, len(tools))
	return nil
}

func (s *Server) discoverAndCacheMCP(ctx context.Context, id int64, requireEnabled bool) error {
	if s == nil || s.m == nil || s.m.pg == nil {
		return errMCPDiscoveryDenied
	}
	return discoverMCP(ctx, s.m.pg, id, requireEnabled, connectMCP)
}
