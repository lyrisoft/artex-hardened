package db

import (
	"context"
	"errors"
	"testing"
)

func TestResolveVerifiedPrincipalRequiresExactEnabledIdentity(t *testing.T) {
	d, err := Open(scratchDSN(t, "verified_principal"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var id int64
	if err := d.QueryRow(`INSERT INTO security_principals(kind,issuer,subject) VALUES ('human','fixture-issuer','Alice') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	deny := func(issuer, subject, kind string) {
		t.Helper()
		p, err := d.ResolveVerifiedPrincipal(context.Background(), issuer, subject, kind)
		if p != nil || !errors.Is(err, ErrPrincipalAccessDenied) {
			t.Fatalf("issuer=%q subject=%q kind=%q principal=%+v err=%v", issuer, subject, kind, p, err)
		}
	}
	deny("fixture-issuer", "Alice", "human") // disabled by default
	if _, err := d.Exec(`UPDATE security_principals SET enabled=true WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	p, err := d.ResolveVerifiedPrincipal(context.Background(), "fixture-issuer", "Alice", "human")
	if err != nil || p.ID != id || p.Kind != "human" || p.AuthEpoch != 1 {
		t.Fatalf("principal=%+v err=%v", p, err)
	}
	deny("fixture-issuer", "alice", "human")
	deny("other-issuer", "Alice", "human")
	deny("fixture-issuer", "Alice", "service")
	deny("fixture-issuer", "Alice", "agent")
	deny(" ", "Alice", "human")
	for _, query := range []string{
		`UPDATE security_principals SET issuer='other-issuer' WHERE id=$1`,
		`UPDATE security_principals SET subject='Bob' WHERE id=$1`,
		`UPDATE security_principals SET kind='service' WHERE id=$1`,
	} {
		if _, err := d.Exec(query, id); err == nil {
			t.Fatalf("principal identity was reassigned: %s", query)
		}
	}
	if p, err := d.ResolveVerifiedPrincipal(context.Background(), "fixture-issuer", "Alice", "human"); err != nil || p.ID != id {
		t.Fatalf("original binding changed: principal=%+v err=%v", p, err)
	}
	if _, err := d.Exec(`UPDATE security_principals SET enabled=false WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	deny("fixture-issuer", "Alice", "human")
	if _, err := d.Exec(`UPDATE security_principals SET enabled=true WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	p, err = d.ResolveVerifiedPrincipal(context.Background(), "fixture-issuer", "Alice", "human")
	if err != nil || p.AuthEpoch != 2 {
		t.Fatalf("disable did not advance authentication generation: principal=%+v err=%v", p, err)
	}
	if _, err := d.Exec(`UPDATE security_principals SET auth_epoch=1 WHERE id=$1`, id); err == nil {
		t.Fatal("authentication generation was rolled back")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := d.ResolveVerifiedPrincipal(ctx, "fixture-issuer", "Alice", "human"); p != nil || err == nil {
		t.Fatalf("cancelled lookup=%+v err=%v", p, err)
	}
	if p, err := (*DB)(nil).ResolveVerifiedPrincipal(context.Background(), "fixture-issuer", "Alice", "human"); p != nil || !errors.Is(err, ErrPrincipalAccessDenied) {
		t.Fatalf("nil DB lookup=%+v err=%v", p, err)
	}
}
