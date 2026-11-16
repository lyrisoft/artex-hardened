package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type admissionFixture struct {
	db                                                *DB
	tenant, team, workspace, task, scope, reservation int64
	requester, approver, executor                     int64
	requesterGrant, approverGrant, executorGrant      int64
}

func newAdmissionFixture(t *testing.T, suffix string) admissionFixture {
	t.Helper()
	d, err := Open(scratchDSN(t, suffix))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return makeAdmissionFixture(t, d)
}

func makeAdmissionFixture(t *testing.T, d *DB) admissionFixture {
	return makeExpiringAdmissionFixture(t, d, time.Hour, 0)
}

func makeExpiringAdmissionFixture(t *testing.T, d *DB, scopeLifetime, executorLifetime time.Duration) admissionFixture {
	t.Helper()
	id := func(query string, args ...any) int64 {
		t.Helper()
		var value int64
		if err := d.QueryRow(query, args...).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := d.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	f := admissionFixture{db: d}
	f.tenant = id(`INSERT INTO security_tenants(name,enabled) VALUES ('fixture',true) RETURNING id`)
	f.team = id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','fixture',true) RETURNING id`, f.tenant)
	f.workspace = id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'fixture',true) RETURNING id`, f.tenant, f.team)
	person := func(kind, subject, role string) (int64, int64) {
		principal := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ($1,'fixture',$2,true) RETURNING id`, kind, subject)
		var expires any
		if subject == "executor" && executorLifetime > 0 {
			expires = time.Now().UTC().Add(executorLifetime)
		}
		grant := id(`INSERT INTO security_team_memberships(team_id,principal_id,role,expires_at) VALUES ($1,$2,$3,$4) RETURNING id`, f.team, principal, role, expires)
		return principal, grant
	}
	f.requester, f.requesterGrant = person("human", "requester", "operator")
	f.approver, f.approverGrant = person("human", "approver", "approver")
	f.executor, f.executorGrant = person("service", "executor", "operator")
	task, err := d.CreateTask("synthetic admission", "fixture", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	f.task = task.ID
	exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2)`, f.workspace, f.task)
	doc := []byte(`{"version":1,"targets":[{"address":"172.30.139.20","port":80,"methods":["tcp.connect"]}]}`)
	now := time.Now().UTC()
	ctx := context.Background()
	f.scope, err = d.ProposeSyntheticScope(ctx, f.requester, 1, f.workspace, f.task, doc, now.Add(-time.Minute), now.Add(scopeLifetime))
	if err != nil {
		t.Fatal(err)
	}
	review, err := d.ProposedSyntheticScope(ctx, f.approver, 1, f.workspace, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ApproveSyntheticScope(ctx, f.approver, 1, f.workspace, f.scope, review.DecisionSHA256); err != nil {
		t.Fatal(err)
	}
	reservation, err := d.ReserveSyntheticFixtureRun(ctx, f.requester, 1, f.workspace, f.scope, f.executor, 1, review.DecisionSHA256, doc)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation = reservation.ID
	return f
}

// Wait for a real PostgreSQL lock dependency, rather than assuming a goroutine
// has reached a particular SQL statement after an arbitrary sleep.
func waitForAdmissionBlock(t *testing.T, ctx context.Context, d *DB, waiter, blocker int) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := d.QueryRowContext(ctx, `SELECT $2=ANY(pg_blocking_pids($1))`, waiter, blocker).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("backend %d did not wait for backend %d: %v", waiter, blocker, ctx.Err())
		case <-ticker.C:
		}
	}
}

func admissionBackendPID(t *testing.T, tx *sql.Tx) int {
	t.Helper()
	var pid int
	if err := tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

func TestInactiveAdmissionSerializesEligibilityChanges(t *testing.T) {
	type mutation struct {
		name  string
		apply func(*sql.Tx, admissionFixture) error
	}
	update := func(query string, id func(admissionFixture) int64) func(*sql.Tx, admissionFixture) error {
		return func(tx *sql.Tx, f admissionFixture) error { _, err := tx.Exec(query, id(f)); return err }
	}
	changes := []mutation{
		{"scope", func(tx *sql.Tx, f admissionFixture) error {
			_, err := tx.Exec(`INSERT INTO security_scope_revocations(proposal_id,revoker_id,reason) VALUES ($1,$2,'fixture')`, f.scope, f.approver)
			return err
		}},
		{"requester_grant", update(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, func(f admissionFixture) int64 { return f.requesterGrant })},
		{"approver_grant", update(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, func(f admissionFixture) int64 { return f.approverGrant })},
		{"executor_grant", update(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, func(f admissionFixture) int64 { return f.executorGrant })},
		{"requester_identity", update(`UPDATE security_principals SET enabled=false WHERE id=$1`, func(f admissionFixture) int64 { return f.requester })},
		{"approver_identity", update(`UPDATE security_principals SET enabled=false WHERE id=$1`, func(f admissionFixture) int64 { return f.approver })},
		{"executor_identity", update(`UPDATE security_principals SET enabled=false WHERE id=$1`, func(f admissionFixture) int64 { return f.executor })},
		{"workspace", update(`UPDATE security_workspaces SET enabled=false WHERE id=$1`, func(f admissionFixture) int64 { return f.workspace })},
		{"team", update(`UPDATE security_teams SET enabled=false WHERE id=$1`, func(f admissionFixture) int64 { return f.team })},
		{"tenant", update(`UPDATE security_tenants SET enabled=false WHERE id=$1`, func(f admissionFixture) int64 { return f.tenant })},
		{"task", update(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, func(f admissionFixture) int64 { return f.task })},
	}
	for i, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			f := newAdmissionFixture(t, fmt.Sprintf("admit_%02d", i))
			assertInvalidationWins(t, f, change.apply, sql.LevelReadCommitted, false)
		})
	}
	// Even a transaction whose snapshot predates the committed revocation must
	// abort instead of using a stale eligibility view.
	for _, level := range []struct {
		name  string
		value sql.IsolationLevel
	}{{"repeatable_read", sql.LevelRepeatableRead}, {"serializable", sql.LevelSerializable}} {
		for i := 0; i < 2; i++ {
			change := changes[i]
			t.Run(level.name+"_"+change.name, func(t *testing.T) {
				f := newAdmissionFixture(t, fmt.Sprintf("admit_%s_%02d", level.name, i))
				assertInvalidationWins(t, f, change.apply, level.value, true)
			})
		}
	}
}

func assertInvalidationWins(t *testing.T, f admissionFixture, mutate func(*sql.Tx, admissionFixture) error, iso sql.IsolationLevel, serializationFailure bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	starter, err := f.db.BeginTx(ctx, &sql.TxOptions{Isolation: iso})
	if err != nil {
		t.Fatal(err)
	}
	defer starter.Rollback()
	starterPID := admissionBackendPID(t, starter)
	// Establish the starter snapshot before the invalidation transaction commits.
	var before int64
	if err := starter.QueryRowContext(ctx, `SELECT generation FROM security_admission_epoch WHERE singleton=true`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	invalidator, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer invalidator.Rollback()
	invalidatorPID := admissionBackendPID(t, invalidator)
	if err := mutate(invalidator, f); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := starter.ExecContext(ctx, `UPDATE security_run_reservations SET state='running' WHERE id=$1`, f.reservation)
		done <- err
	}()
	waitForAdmissionBlock(t, ctx, f.db, starterPID, invalidatorPID)
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
	if !errors.As(startErr, &pgErr) {
		t.Fatalf("start error=%v, want database denial", startErr)
	}
	if serializationFailure {
		if pgErr.Code != "40001" {
			t.Fatalf("start error=%v, want serialization failure", startErr)
		}
	} else if pgErr.Code != "P0001" || !strings.Contains(pgErr.Message, "no longer eligible") {
		t.Fatalf("start error=%v, want eligibility denial", startErr)
	}
	if err := starter.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		t.Fatal(err)
	}
	var state string
	if err := f.db.QueryRowContext(ctx, `SELECT state FROM security_run_reservations WHERE id=$1`, f.reservation).Scan(&state); err != nil || state != "reserved" {
		t.Fatalf("reservation state=%q err=%v", state, err)
	}
}

func TestInactiveAdmissionStartWinsBeforeLaterRevocation(t *testing.T) {
	f := newAdmissionFixture(t, "admit_start_first")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	starter, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer starter.Rollback()
	starterPID := admissionBackendPID(t, starter)
	if _, err := starter.ExecContext(ctx, `UPDATE security_run_reservations SET state='running' WHERE id=$1`, f.reservation); err != nil {
		t.Fatal(err)
	}
	invalidator, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer invalidator.Rollback()
	invalidatorPID := admissionBackendPID(t, invalidator)
	done := make(chan error, 1)
	go func() {
		_, err := invalidator.ExecContext(ctx, `INSERT INTO security_scope_revocations(proposal_id,revoker_id,reason) VALUES ($1,$2,'fixture')`, f.scope, f.approver)
		done <- err
	}()
	waitForAdmissionBlock(t, ctx, f.db, invalidatorPID, starterPID)
	if err := starter.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := invalidator.Commit(); err != nil {
		t.Fatal(err)
	}
	var state string
	var revoked bool
	if err := f.db.QueryRowContext(ctx, `SELECT state,EXISTS(SELECT 1 FROM security_scope_revocations WHERE proposal_id=$2) FROM security_run_reservations WHERE id=$1`, f.reservation, f.scope).Scan(&state, &revoked); err != nil || state != "running" || !revoked {
		t.Fatalf("state=%q revoked=%v err=%v", state, revoked, err)
	}
	// No real process is running. A future supervisor must interrupt an active
	// process when a revocation follows a successful start.
}

func TestInactiveAdmissionEpochCannotBeRemovedOrRewound(t *testing.T) {
	f := newAdmissionFixture(t, "admit_epoch_guard")
	for _, q := range []string{`UPDATE security_admission_epoch SET generation=generation`, `DELETE FROM security_admission_epoch`, `TRUNCATE security_admission_epoch`} {
		if _, err := f.db.Exec(q); err == nil {
			t.Fatalf("unsafe epoch mutation allowed: %s", q)
		}
	}
}

func TestInactiveAdmissionRolledBackRevocationDoesNotBlockStart(t *testing.T) {
	f := newAdmissionFixture(t, "admit_rollback")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	invalidator, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer invalidator.Rollback()
	invalidatorPID := admissionBackendPID(t, invalidator)
	if _, err := invalidator.ExecContext(ctx, `INSERT INTO security_scope_revocations(proposal_id,revoker_id,reason) VALUES ($1,$2,'fixture')`, f.scope, f.approver); err != nil {
		t.Fatal(err)
	}
	starter, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer starter.Rollback()
	starterPID := admissionBackendPID(t, starter)
	done := make(chan error, 1)
	go func() {
		_, err := starter.ExecContext(ctx, `UPDATE security_run_reservations SET state='running' WHERE id=$1`, f.reservation)
		done <- err
	}()
	waitForAdmissionBlock(t, ctx, f.db, starterPID, invalidatorPID)
	if err := invalidator.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := starter.Commit(); err != nil {
		t.Fatal(err)
	}
	var state string
	var revoked bool
	if err := f.db.QueryRowContext(ctx, `SELECT state,EXISTS(SELECT 1 FROM security_scope_revocations WHERE proposal_id=$2) FROM security_run_reservations WHERE id=$1`, f.reservation, f.scope).Scan(&state, &revoked); err != nil || state != "running" || revoked {
		t.Fatalf("state=%q revoked=%v err=%v", state, revoked, err)
	}
}

// An upgrade keeps an existing inactive reservation and applies the barrier to
// its future state transitions without rewriting its authorization history.
func TestInactiveAdmissionUpgradePreservesExistingReservation(t *testing.T) {
	dsn := scratchDSN(t, "admit_upgrade")
	old := fstest.MapFS{}
	entries, err := fs.ReadDir(migrationsFS(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") || name >= "0011" {
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
	var proposal int64
	if err := d.QueryRow(`SELECT state,scope_proposal_id FROM security_run_reservations WHERE id=$1`, f.reservation).Scan(&state, &proposal); err != nil || state != "reserved" || proposal != f.scope {
		t.Fatalf("upgrade changed reservation: state=%q proposal=%d err=%v", state, proposal, err)
	}
	assertInvalidationWins(t, f, func(tx *sql.Tx, f admissionFixture) error {
		_, err := tx.Exec(`INSERT INTO security_scope_revocations(proposal_id,revoker_id,reason) VALUES ($1,$2,'fixture')`, f.scope, f.approver)
		return err
	}, sql.LevelReadCommitted, false)
}

func TestInactiveAdmissionExpiryWhileWaitingFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		scopeLifetime, executorLifetime time.Duration
		expiredSQL                      string
	}{
		{"scope", 3 * time.Second, 0, `SELECT clock_timestamp() >= valid_until FROM security_run_reservations WHERE id=$1`},
		{"executor_grant", time.Hour, 3 * time.Second, `SELECT clock_timestamp() >= expires_at FROM security_team_memberships WHERE id=$1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Open(scratchDSN(t, "admit_expiry_"+tc.name))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { d.Close() })
			f := makeExpiringAdmissionFixture(t, d, tc.scopeLifetime, tc.executorLifetime)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			blocker, err := d.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			blockerPID := admissionBackendPID(t, blocker)
			if _, err := blocker.ExecContext(ctx, `UPDATE security_admission_epoch SET generation=generation+1 WHERE singleton=true`); err != nil {
				t.Fatal(err)
			}
			starter, err := d.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer starter.Rollback()
			starterPID := admissionBackendPID(t, starter)
			done := make(chan error, 1)
			go func() {
				_, err := starter.ExecContext(ctx, `UPDATE security_run_reservations SET state='running' WHERE id=$1`, f.reservation)
				done <- err
			}()
			waitForAdmissionBlock(t, ctx, d, starterPID, blockerPID)
			id := f.reservation
			if tc.name == "executor_grant" {
				id = f.executorGrant
			}
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for {
				var expired bool
				if err := d.QueryRowContext(ctx, tc.expiredSQL, id).Scan(&expired); err != nil {
					t.Fatal(err)
				}
				if expired {
					break
				}
				select {
				case <-ticker.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if err := blocker.Commit(); err != nil {
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
				t.Fatalf("expired authorization start error=%v", startErr)
			}
		})
	}
}
