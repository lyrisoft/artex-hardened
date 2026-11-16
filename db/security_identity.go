package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// SecurityPrincipal is a persisted human or service identity. It conveys no
// workspace membership, role, target access or permission to perform an action.
type SecurityPrincipal struct {
	ID        int64
	AuthEpoch int64
	Kind      string
	Issuer    string
	Subject   string
}

var ErrPrincipalAccessDenied = errors.New("principal access denied")

// ResolveVerifiedPrincipal maps an already independently verified identity to
// an enabled record. Issuer, subject and kind MUST come from a trusted verifier
// that checked issuer, signature, audience, expiry and the appropriate credential
// type; untrusted HTTP parameters, unverified JWT claims, the legacy shared
// password, agent output and this function alone are not authentication. The
// function does not create users or memberships and is not wired to the API.
func (d *DB) ResolveVerifiedPrincipal(ctx context.Context, issuer, subject, kind string) (*SecurityPrincipal, error) {
	if d == nil || d.DB == nil || strings.TrimSpace(issuer) == "" || strings.TrimSpace(subject) == "" || len(issuer) > 2048 || len(subject) > 2048 || (kind != "human" && kind != "service") {
		return nil, ErrPrincipalAccessDenied
	}
	var p SecurityPrincipal
	err := d.QueryRowContext(ctx, `SELECT id,auth_epoch,kind,issuer,subject FROM security_principals WHERE issuer=$1 AND subject=$2 AND kind=$3 AND enabled`, issuer, subject, kind).Scan(&p.ID, &p.AuthEpoch, &p.Kind, &p.Issuer, &p.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPrincipalAccessDenied
	}
	if err != nil {
		return nil, fmt.Errorf("resolve verified principal: %w", err)
	}
	return &p, nil
}
