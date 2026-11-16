package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/security/oidclogin"
)

type verifiedHumanStore interface {
	ResolveVerifiedPrincipal(context.Context, string, string, string) (*db.SecurityPrincipal, error)
}

type teamHumanResolver struct{ store verifiedHumanStore }

func (r teamHumanResolver) ResolveHuman(ctx context.Context, issuer, subject string) (oidclogin.Human, error) {
	if r.store == nil {
		return oidclogin.Human{}, db.ErrPrincipalAccessDenied
	}
	p, err := r.store.ResolveVerifiedPrincipal(ctx, issuer, subject, "human")
	if err != nil {
		return oidclogin.Human{}, err
	}
	if p == nil || p.ID <= 0 || p.AuthEpoch <= 0 || p.Kind != "human" || p.Issuer != issuer || p.Subject != subject {
		return oidclogin.Human{}, db.ErrPrincipalAccessDenied
	}
	return oidclogin.Human{ID: p.ID, AuthEpoch: p.AuthEpoch}, nil
}

// NewTeamOIDC constructs the separate human login component. It is not called
// from the legacy server or main; selecting a real provider and mounting this
// handler require the separately approved operational rollout.
func NewTeamOIDC(ctx context.Context, cfg oidclogin.Config, pg *db.DB) (*oidclogin.Flow, error) {
	if pg == nil || pg.DB == nil {
		return nil, errors.New("team identity store unavailable")
	}
	return oidclogin.New(ctx, cfg, teamHumanResolver{store: pg})
}

// NewTeamHandler returns an isolated, read-only route tree. It does not fall
// back to the shared-password router and is not mounted by the existing server.
// This is not a runner, evidence service, or complete workspace application.
func NewTeamHandler(flow *oidclogin.Flow, pg *db.DB) (http.Handler, error) {
	if flow == nil || pg == nil || pg.DB == nil {
		return nil, errors.New("team handler dependencies unavailable")
	}
	callback, after := flow.RoutePaths()
	if callback != "/team/auth/callback" || after != "/team" {
		return nil, errors.New("team authentication route mismatch")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /team/auth/start", flow.Start)
	mux.HandleFunc("GET /team/auth/callback", flow.Callback)
	mux.HandleFunc("POST /team/auth/logout", flow.Logout)
	mux.Handle("GET /team", flow.RequireHuman(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		human, ok := oidclogin.HumanFromContext(r.Context())
		if !ok {
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}
		writeTeamJSON(w, map[string]any{"principal_id": human.ID})
	})))
	mux.Handle("GET /team/api/workspaces", flow.RequireHuman(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		human, ok := oidclogin.HumanFromContext(r.Context())
		afterID, limit, valid := teamPage(r)
		if !ok || !valid {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		items, err := pg.HumanWorkspaces(r.Context(), human.ID, human.AuthEpoch, afterID, limit)
		if err != nil {
			http.Error(w, "data source unavailable", http.StatusServiceUnavailable)
			return
		}
		var next int64
		if len(items) == limit {
			next = items[len(items)-1].ID
		}
		writeTeamJSON(w, map[string]any{"workspaces": items, "next_cursor": next})
	})))
	mux.Handle("GET /team/api/workspaces/{workspace}/tasks", flow.RequireHuman(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		human, ok := oidclogin.HumanFromContext(r.Context())
		workspace, workspaceOK := teamInt(r.PathValue("workspace"), false)
		afterID, limit, valid := teamPage(r)
		if !ok || !workspaceOK || !valid {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		items, err := pg.HumanWorkspaceTasks(r.Context(), human.ID, human.AuthEpoch, workspace, afterID, limit)
		if err != nil {
			http.Error(w, "data source unavailable", http.StatusServiceUnavailable)
			return
		}
		var next int64
		if len(items) == limit {
			next = items[len(items)-1].ID
		}
		writeTeamJSON(w, map[string]any{"tasks": items, "next_cursor": next})
	})))
	return mux, nil
}

func writeTeamJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

func teamPage(r *http.Request) (int64, int, bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, 0, false
	}
	for key, values := range q {
		if (key != "after" && key != "limit") || len(values) != 1 {
			return 0, 0, false
		}
	}
	var after int64
	limit := 50
	if _, exists := q["after"]; exists {
		var ok bool
		after, ok = teamInt(q.Get("after"), true)
		if !ok {
			return 0, 0, false
		}
	}
	if _, exists := q["limit"]; exists {
		value, ok := teamInt(q.Get("limit"), false)
		if !ok || value > 100 {
			return 0, 0, false
		}
		limit = int(value)
	}
	return after, limit, true
}

func teamInt(value string, zeroAllowed bool) (int64, bool) {
	if value == "" {
		return 0, false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil && (n > 0 || (zeroAllowed && n == 0))
}
