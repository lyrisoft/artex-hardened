package db

import (
	"context"
	"errors"
	"testing"
)

func TestResolveWorkspaceMembership(t *testing.T) {
	dsn := scratchDSN(t, "workspace_membership")
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	id := func(query string, args ...any) int64 {
		t.Helper()
		var value int64
		if err := d.QueryRow(query, args...).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	tenant := id(`INSERT INTO security_tenants(name) VALUES ('synthetic') RETURNING id`)
	principal := id(`INSERT INTO security_principals(kind,issuer,subject) VALUES ('human','fixture','alice') RETURNING id`)
	otherPrincipal := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ('human','fixture','bob',true) RETURNING id`)
	team := id(`INSERT INTO security_teams(tenant_id,kind,name) VALUES ($1,'red','red') RETURNING id`, tenant)
	workspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name) VALUES ($1,$2,'red workspace') RETURNING id`, tenant, team)
	otherTeam := id(`INSERT INTO security_teams(tenant_id,kind,name) VALUES ($1,'blue','blue') RETURNING id`, tenant)
	otherWorkspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name) VALUES ($1,$2,'blue workspace') RETURNING id`, tenant, otherTeam)
	if _, err := d.Exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, team, principal); err == nil {
		t.Fatal("grant issued to a disabled principal")
	}
	if _, err := d.Exec(`UPDATE security_principals SET enabled=true WHERE id=$1`, principal); err != nil {
		t.Fatal(err)
	}
	membership := id(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator') RETURNING id`, team, principal)
	epoch := int64(1)
	deny := func(principalID, workspaceID int64) {
		t.Helper()
		got, err := d.ResolveWorkspaceMembership(context.Background(), principalID, epoch, workspaceID)
		if got != nil || !errors.Is(err, ErrWorkspaceAccessDenied) {
			t.Fatalf("principal=%d workspace=%d: got=%+v err=%v; want generic denial", principalID, workspaceID, got, err)
		}
	}
	deny(principal, workspace) // tenant, team, and workspace are disabled by default
	for _, q := range []string{
		`UPDATE security_tenants SET enabled=true WHERE id=$1`,
		`UPDATE security_principals SET enabled=true WHERE id=$1`,
		`UPDATE security_teams SET enabled=true WHERE id=$1`,
		`UPDATE security_workspaces SET enabled=true WHERE id=$1`,
	} {
		var value int64
		switch q {
		case `UPDATE security_tenants SET enabled=true WHERE id=$1`:
			value = tenant
		case `UPDATE security_principals SET enabled=true WHERE id=$1`:
			value = principal
		case `UPDATE security_teams SET enabled=true WHERE id=$1`:
			value = team
		default:
			value = workspace
		}
		if _, err := d.Exec(q, value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`UPDATE security_teams SET enabled=true WHERE id=$1`, otherTeam); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE security_workspaces SET enabled=true WHERE id=$1`, otherWorkspace); err != nil {
		t.Fatal(err)
	}
	got, err := d.ResolveWorkspaceMembership(context.Background(), principal, epoch, workspace)
	if err != nil || got == nil || got.PrincipalID != principal || got.PrincipalKind != "human" || got.Role != "operator" || got.TenantID != tenant || got.TeamID != team || got.TeamKind != "red" || got.WorkspaceID != workspace {
		t.Fatalf("resolved membership = %+v, err=%v", got, err)
	}
	deny(principal, otherWorkspace) // enabled team and workspace, but no membership
	deny(otherPrincipal, workspace) // enabled principal, but no membership
	deny(principal+99999, workspace)
	deny(0, workspace)
	deny(principal, 0)

	for _, tc := range []struct {
		name, disable, enable string
		id                    int64
	}{
		{"principal", `UPDATE security_principals SET enabled=false WHERE id=$1`, `UPDATE security_principals SET enabled=true WHERE id=$1`, principal},
		{"tenant", `UPDATE security_tenants SET enabled=false WHERE id=$1`, `UPDATE security_tenants SET enabled=true WHERE id=$1`, tenant},
		{"team", `UPDATE security_teams SET enabled=false WHERE id=$1`, `UPDATE security_teams SET enabled=true WHERE id=$1`, team},
		{"workspace", `UPDATE security_workspaces SET enabled=false WHERE id=$1`, `UPDATE security_workspaces SET enabled=true WHERE id=$1`, workspace},
	} {
		if _, err := d.Exec(tc.disable, tc.id); err != nil {
			t.Fatalf("disable %s: %v", tc.name, err)
		}
		deny(principal, workspace)
		if _, err := d.Exec(tc.enable, tc.id); err != nil {
			t.Fatalf("enable %s: %v", tc.name, err)
		}
		if tc.name == "principal" {
			epoch = 2
			// Re-enabling the identity must not revive a pre-disable grant.
			deny(principal, workspace)
			if _, err := d.Exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, membership); err != nil {
				t.Fatal(err)
			}
			membership = id(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator') RETURNING id`, team, principal)
			if stale, err := d.ResolveWorkspaceMembership(context.Background(), principal, 1, workspace); stale != nil || !errors.Is(err, ErrWorkspaceAccessDenied) {
				t.Fatalf("stale session gained new membership: %+v err=%v", stale, err)
			}
		}
	}
	for _, query := range []string{
		`UPDATE security_team_memberships SET role='manager' WHERE id=$1`,
		`UPDATE security_team_memberships SET valid_from=now()-interval '1 day' WHERE id=$1`,
		`UPDATE security_team_memberships SET expires_at=now()+interval '1 day' WHERE id=$1`,
	} {
		if _, err := d.Exec(query, membership); err == nil {
			t.Fatalf("membership grant could be changed: %s", query)
		}
	}
	revoke := func(grant int64) {
		t.Helper()
		if _, err := d.Exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, grant); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`UPDATE security_team_memberships SET revoked_at=NULL WHERE id=$1`, grant); err == nil {
			t.Fatal("membership revocation could be undone")
		}
	}
	revoke(membership)
	deny(principal, workspace)
	future := id(`INSERT INTO security_team_memberships(team_id,principal_id,role,valid_from) VALUES ($1,$2,'operator',now()+interval '1 day') RETURNING id`, team, principal)
	deny(principal, workspace)
	revoke(future)
	expired := id(`INSERT INTO security_team_memberships(team_id,principal_id,role,valid_from,expires_at) VALUES ($1,$2,'operator',now()-interval '2 days',now()-interval '1 day') RETURNING id`, team, principal)
	deny(principal, workspace)
	revoke(expired)
	current := id(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator') RETURNING id`, team, principal)
	if _, err := d.ResolveWorkspaceMembership(context.Background(), principal, epoch, workspace); err != nil {
		t.Fatalf("new grant not resolved: %v", err)
	}
	revoke(current)
	deny(principal, workspace)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := d.ResolveWorkspaceMembership(ctx, principal, epoch, workspace); got != nil || err == nil {
		t.Fatalf("cancelled lookup must fail closed: got=%+v err=%v", got, err)
	}
	if got, err := (*DB)(nil).ResolveWorkspaceMembership(context.Background(), principal, epoch, workspace); got != nil || err == nil {
		t.Fatalf("unavailable store must fail closed: got=%+v err=%v", got, err)
	}
}
