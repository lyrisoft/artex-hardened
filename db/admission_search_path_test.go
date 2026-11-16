package db

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// The caller can normally create temporary tables. Trigger-side lookups must
// use the migration's real schema, even when the calling session prefers temp.
func TestAdmissionTriggersIgnoreTemporaryShadowTables(t *testing.T) {
	f := newAdmissionFixture(t, "admit_shadow")
	assertAdmissionShadowDenied(t, f, "public")
}

func assertAdmissionShadowDenied(t *testing.T, f admissionFixture, schema string) {
	t.Helper()
	if schema != "public" && schema != "fixture_team" {
		t.Fatal("unexpected test schema")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := f.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `CREATE TEMP TABLE security_admission_epoch(singleton boolean PRIMARY KEY,generation bigint); INSERT INTO pg_temp.security_admission_epoch VALUES (true,0); CREATE TEMP TABLE security_scope_revocations(proposal_id bigint); SET search_path=pg_temp,`+schema+`,public`); err != nil {
		t.Fatal(err)
	}
	starter, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer starter.Rollback()
	starterPID := admissionBackendPID(t, starter)
	invalidator, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer invalidator.Rollback()
	invalidatorPID := admissionBackendPID(t, invalidator)
	if _, err := invalidator.ExecContext(ctx, `INSERT INTO `+schema+`.security_scope_revocations(proposal_id,revoker_id,reason) VALUES ($1,$2,'fixture')`, f.scope, f.approver); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := starter.ExecContext(ctx, `UPDATE `+schema+`.security_run_reservations SET state='running' WHERE id=$1`, f.reservation)
		done <- err
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := f.db.QueryRowContext(ctx, `SELECT $2=ANY(pg_blocking_pids($1))`, starterPID, invalidatorPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("temporary shadow bypassed admission barrier: %v", err)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := invalidator.Commit(); err != nil {
		t.Fatal(err)
	}
	var startErr error
	select {
	case startErr = <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var pgErr *pgconn.PgError
	if !errors.As(startErr, &pgErr) || pgErr.Code != "P0001" || !strings.Contains(pgErr.Message, "no longer eligible") {
		t.Fatalf("revoked admission error=%v", startErr)
	}
}

func TestMembershipTriggerIgnoresTemporaryPrincipalShadow(t *testing.T) {
	f := newAdmissionFixture(t, "membership_shadow")
	if _, err := f.db.Exec(`UPDATE security_principals SET enabled=false WHERE id=$1`, f.executor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, f.executorGrant); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := f.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `CREATE TEMP TABLE security_principals(id bigint,enabled boolean,auth_epoch bigint); SET search_path=pg_temp,public`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO pg_temp.security_principals VALUES ($1,true,2)`, f.executor); err != nil {
		t.Fatal(err)
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO public.security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, f.team, f.executor)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" || !strings.Contains(pgErr.Message, "generation mismatch") {
		t.Fatalf("disabled principal membership accepted or wrong error: %v", err)
	}
}

func TestSecurityTriggerSearchPathUpgradePreservesReservation(t *testing.T) {
	dsn := scratchDSN(t, "shadow_upgrade")
	old := fstest.MapFS{}
	entries, err := fs.ReadDir(migrationsFS(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") || name >= "0012" {
			continue
		}
		content, err := fs.ReadFile(migrationsFS(), name)
		if err != nil {
			t.Fatal(err)
		}
		old[name] = &fstest.MapFile{Data: content}
	}
	d, err := openWithMigrations(dsn, old)
	if err != nil {
		t.Fatal(err)
	}
	f := makeAdmissionFixture(t, d)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	f.db = d
	var state string
	if err := d.QueryRow(`SELECT state FROM security_run_reservations WHERE id=$1`, f.reservation).Scan(&state); err != nil || state != "reserved" {
		t.Fatalf("reservation after upgrade=%q err=%v", state, err)
	}
	assertAdmissionShadowDenied(t, f, "public")
}

func TestSecurityTriggerSearchPathUsesInstalledSchema(t *testing.T) {
	dsn := scratchDSN(t, "shadow_custom_schema")
	if err := ensureDatabase(dsn); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`CREATE SCHEMA fixture_team`); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if err := admin.Close(); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", "fixture_team,public")
	u.RawQuery = q.Encode()
	d, err := Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	f := makeAdmissionFixture(t, d)
	assertAdmissionShadowDenied(t, f, "fixture_team")
}
