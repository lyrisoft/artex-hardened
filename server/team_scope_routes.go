package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/security/oidclogin"
	"github.com/Autumn-27/artex/security/strictjson"
)

const maxTeamScopeRequest = 70 * 1024

// registerTeamScopeRoutes exposes inert scope records only. It does not start
// an agent, issue credentials or authorize traffic. This handler tree is not
// mounted by the legacy server and requires independently provisioned humans.
func registerTeamScopeRoutes(mux *http.ServeMux, flow *oidclogin.Flow, pg *db.DB) {
	mux.Handle("POST /team/api/workspaces/{workspace}/tasks/{task}/scope-proposals", flow.RequireHuman(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		human, ok := oidclogin.HumanFromContext(r.Context())
		workspace, workspaceOK := teamInt(r.PathValue("workspace"), false)
		task, taskOK := teamInt(r.PathValue("task"), false)
		fields, valid := scopeRequest(r, "valid_from", "valid_until", "document")
		if !ok || !workspaceOK || !taskOK || !valid {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var fromText, untilText string
		if json.Unmarshal(fields["valid_from"], &fromText) != nil || json.Unmarshal(fields["valid_until"], &untilText) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		from, err1 := time.Parse(time.RFC3339Nano, fromText)
		until, err2 := time.Parse(time.RFC3339Nano, untilText)
		if err1 != nil || err2 != nil || !until.After(from) {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		id, err := pg.ProposeSyntheticScope(r.Context(), human.ID, human.AuthEpoch, workspace, task, fields["document"], from, until)
		if err != nil {
			teamScopeError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"proposal_id": id})
	})))

	mux.Handle("GET /team/api/workspaces/{workspace}/scope-proposals/{proposal}", flow.RequireHuman(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		human, workspace, proposal, valid := scopeActorAndPath(r)
		if !valid {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		scope, err := pg.ProposedSyntheticScope(r.Context(), human.ID, human.AuthEpoch, workspace, proposal)
		if err != nil {
			teamScopeError(w, err)
			return
		}
		// Serve the exact persisted bytes. Headers provide the bound fields an
		// independent approver must inspect before confirming the decision digest.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Artex-Task-Id", formatTeamID(scope.TaskID))
		w.Header().Set("X-Artex-Requester-Id", formatTeamID(scope.RequesterID))
		w.Header().Set("X-Artex-Valid-From", scope.ValidFrom.UTC().Format(time.RFC3339Nano))
		w.Header().Set("X-Artex-Valid-Until", scope.ValidUntil.UTC().Format(time.RFC3339Nano))
		w.Header().Set("X-Artex-Document-Sha256", hex.EncodeToString(scope.SHA256[:]))
		w.Header().Set("X-Artex-Decision-Sha256", hex.EncodeToString(scope.DecisionSHA256[:]))
		_, _ = w.Write(scope.Document)
	})))

	mux.Handle("POST /team/api/workspaces/{workspace}/scope-proposals/{proposal}/approve", flow.RequireHuman(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		human, workspace, proposal, valid := scopeActorAndPath(r)
		fields, fieldsOK := scopeRequest(r, "decision_sha256")
		var encoded string
		if !valid || !fieldsOK || json.Unmarshal(fields["decision_sha256"], &encoded) != nil || len(encoded) != sha256.Size*2 || encoded != strings.ToLower(encoded) {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		digest, err := hex.DecodeString(encoded)
		if err != nil || len(digest) != sha256.Size {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var expected [sha256.Size]byte
		copy(expected[:], digest)
		if err := pg.ApproveSyntheticScope(r.Context(), human.ID, human.AuthEpoch, workspace, proposal, expected); err != nil {
			teamScopeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	mux.Handle("POST /team/api/workspaces/{workspace}/scope-proposals/{proposal}/revoke", flow.RequireHuman(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		human, workspace, proposal, valid := scopeActorAndPath(r)
		fields, fieldsOK := scopeRequest(r, "reason")
		var reason string
		if !valid || !fieldsOK || json.Unmarshal(fields["reason"], &reason) != nil || !validScopeReason(reason) {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := pg.RevokeSyntheticScope(r.Context(), human.ID, human.AuthEpoch, workspace, proposal, reason); err != nil {
			teamScopeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
}

func scopeActorAndPath(r *http.Request) (oidclogin.Human, int64, int64, bool) {
	human, ok := oidclogin.HumanFromContext(r.Context())
	workspace, workspaceOK := teamInt(r.PathValue("workspace"), false)
	proposal, proposalOK := teamInt(r.PathValue("proposal"), false)
	return human, workspace, proposal, ok && workspaceOK && proposalOK && r.URL.RawQuery == ""
}

// scopeRequest rejects ambiguous JSON, unknown keys, query parameters, missing
// fields and oversized bodies before any record or approval is written.
func scopeRequest(r *http.Request, keys ...string) (map[string]json.RawMessage, bool) {
	if r == nil || r.Body == nil || r.URL.RawQuery != "" {
		return nil, false
	}
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return nil, false
	}
	media, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || media != "application/json" || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTeamScopeRequest+1))
	if err != nil || !strictjson.ValidObject(body, maxTeamScopeRequest, 32) {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return nil, false
		}
	}
	return fields, true
}

func validScopeReason(reason string) bool {
	if len(reason) > 1024 || strings.TrimSpace(reason) == "" || !utf8.ValidString(reason) {
		return false
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func teamScopeError(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrWorkspaceAccessDenied) {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	http.Error(w, "data source unavailable", http.StatusServiceUnavailable)
}

func formatTeamID(id int64) string { return strconv.FormatInt(id, 10) }
