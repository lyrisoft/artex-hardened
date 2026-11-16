// Package runnercontract defines an inactive configuration check for a future
// isolated executor. It does not launch containers, inspect a running daemon,
// prove egress isolation, authenticate identities, or authorize a target.
package runnercontract

import (
	"errors"
	"regexp"
)

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var ErrUnsafeSpec = errors.New("executor configuration does not meet the inactive isolation contract")

// Spec is a desired configuration, not an attestation. Every field must later be
// compared to independently observed runtime state by the execution control plane.
// No credentials, host bind mounts, or environment values are accepted here.
type Spec struct {
	TeamID                        int64
	TeamKind                      string
	ImageDigest                   string
	UID, GID                      int
	ReadOnlyRoot                  bool
	NoNewPrivileges               bool
	DropAllCapabilities           bool
	DefaultSeccomp                bool
	Privileged                    bool
	HostPID, HostIPC, HostNetwork bool
	HostMounts                    []string
	Environment                   map[string]string
	MemoryBytes                   int64
	CPUQuotaMilli                 int64
	PIDLimit                      int64
	EgressPolicyID                string
	CredentialPolicyID            string
}

// Validate rejects incomplete or unsafe desired configurations. An egress
// policy ID is only a reference; it is not evidence that a broker enforces it.
func Validate(s Spec) error {
	switch s.TeamKind {
	case "red", "blue", "purple":
	default:
		return ErrUnsafeSpec
	}
	if s.TeamID <= 0 || !digestRE.MatchString(s.ImageDigest) || s.UID <= 0 || s.GID <= 0 ||
		!s.ReadOnlyRoot || !s.NoNewPrivileges || !s.DropAllCapabilities || !s.DefaultSeccomp ||
		s.Privileged || s.HostPID || s.HostIPC || s.HostNetwork || len(s.HostMounts) != 0 || len(s.Environment) != 0 ||
		s.MemoryBytes <= 0 || s.CPUQuotaMilli <= 0 || s.PIDLimit <= 0 || s.EgressPolicyID == "" || s.CredentialPolicyID == "" {
		return ErrUnsafeSpec
	}
	return nil
}

// ValidateSeparation checks that teams do not point to the same configured
// egress or credential policy. Different IDs alone do not prove separation of
// enforcement, filesystem, secrets, network namespaces or running processes.
func ValidateSeparation(a, b Spec) error {
	if Validate(a) != nil || Validate(b) != nil || a.TeamID == b.TeamID ||
		a.EgressPolicyID == b.EgressPolicyID || a.CredentialPolicyID == b.CredentialPolicyID {
		return ErrUnsafeSpec
	}
	return nil
}
