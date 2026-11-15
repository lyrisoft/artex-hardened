package runnercontract

import (
	"strings"
	"testing"
)

func TestInactiveExecutorContract(t *testing.T) {
	valid := Spec{TeamID: 1, TeamKind: "red", ImageDigest: "sha256:" + strings.Repeat("a", 64), UID: 65532, GID: 65532, ReadOnlyRoot: true, NoNewPrivileges: true, DropAllCapabilities: true, DefaultSeccomp: true, MemoryBytes: 1 << 28, CPUQuotaMilli: 1000, PIDLimit: 128, EgressPolicyID: "red-egress-fixture", CredentialPolicyID: "red-creds-fixture"}
	if err := Validate(valid); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*Spec)
	}{
		{"root user", func(s *Spec) { s.UID = 0 }}, {"root group", func(s *Spec) { s.GID = 0 }},
		{"mutable image", func(s *Spec) { s.ImageDigest = "latest" }}, {"writable root", func(s *Spec) { s.ReadOnlyRoot = false }},
		{"privilege escalation", func(s *Spec) { s.NoNewPrivileges = false }}, {"capabilities", func(s *Spec) { s.DropAllCapabilities = false }},
		{"missing seccomp", func(s *Spec) { s.DefaultSeccomp = false }}, {"privileged", func(s *Spec) { s.Privileged = true }},
		{"host network", func(s *Spec) { s.HostNetwork = true }}, {"host pid", func(s *Spec) { s.HostPID = true }},
		{"host ipc", func(s *Spec) { s.HostIPC = true }}, {"host mount", func(s *Spec) { s.HostMounts = []string{"/var/run/docker.sock"} }},
		{"environment", func(s *Spec) { s.Environment = map[string]string{"PASSWORD": "synthetic-only"} }},
		{"unbounded memory", func(s *Spec) { s.MemoryBytes = 0 }}, {"unbounded cpu", func(s *Spec) { s.CPUQuotaMilli = 0 }},
		{"unbounded processes", func(s *Spec) { s.PIDLimit = 0 }}, {"no egress policy", func(s *Spec) { s.EgressPolicyID = "" }},
		{"no credential policy", func(s *Spec) { s.CredentialPolicyID = "" }}, {"unknown team", func(s *Spec) { s.TeamKind = "unknown" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := valid
			tc.change(&s)
			if Validate(s) == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	blue := valid
	blue.TeamID = 2
	blue.TeamKind = "blue"
	blue.EgressPolicyID = "blue-egress-fixture"
	blue.CredentialPolicyID = "blue-creds-fixture"
	if ValidateSeparation(valid, blue) != nil {
		t.Fatal("separate fixture policies rejected")
	}
	blue.CredentialPolicyID = valid.CredentialPolicyID
	if ValidateSeparation(valid, blue) == nil {
		t.Fatal("shared credential policy accepted")
	}
	blue.CredentialPolicyID = "blue-creds-fixture"
	blue.EgressPolicyID = valid.EgressPolicyID
	if ValidateSeparation(valid, blue) == nil {
		t.Fatal("shared egress policy accepted")
	}
}
