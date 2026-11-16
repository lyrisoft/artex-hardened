// Package syntheticpolicy parses a deliberately narrow target manifest and
// compares it with a separately supplied fixture inventory. It does not verify
// an approval, prove that an address is synthetic, control a network, enforce a
// time window, or authorize a tool. No runtime currently calls this package.
package syntheticpolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/Autumn-27/artex/security/strictjson"
)

const (
	maxDocumentBytes = 65536
	maxTargets       = 32
)

var ErrUnsafeManifest = errors.New("synthetic target manifest is invalid or exceeds fixture inventory")

type endpoint struct {
	address netip.Addr
	port    uint16
}

type manifest map[endpoint]map[string]struct{}

// Policy is an immutable in-process comparison result. It is not a lease: the
// caller must recheck the underlying human approval, time, revocation and the
// independently administered inventory at each operation and at the network
// boundary. It must not be cached across changes to any of those inputs.
type Policy struct{ allowed manifest }

// Validate recognizes version 1 exact private IPv4 endpoints and a small set of
// explicit methods. The address classification is not proof of nonproduction.
// DNS names, CIDRs, public addresses, IPv6, wildcards and unknown fields fail
// closed until their independent enforcement has been designed and approved.
func Validate(document []byte) error {
	_, err := parse(document)
	return err
}

// Compile permits only endpoint/method pairs that appear in BOTH documents.
// approved must be the exact bytes of a currently valid, independently approved
// scope, and approvedHash must be the digest returned with that approval.
// inventory must come from a separately administered trusted source bound to the
// same tenant and workspace, not an agent or the scope requester. This function
// does not authenticate either. It rejects a digest mismatch or any pair that
// exceeds the independent inventory.
func Compile(approved []byte, approvedHash [sha256.Size]byte, inventory []byte) (*Policy, error) {
	approved = bytes.Clone(approved)
	inventory = bytes.Clone(inventory)
	digest := sha256.Sum256(approved)
	if subtle.ConstantTimeCompare(digest[:], approvedHash[:]) != 1 {
		return nil, ErrUnsafeManifest
	}
	requested, err := parse(approved)
	if err != nil {
		return nil, ErrUnsafeManifest
	}
	permitted, err := parse(inventory)
	if err != nil {
		return nil, ErrUnsafeManifest
	}
	for ep, methods := range requested {
		for method := range methods {
			if _, ok := permitted[ep][method]; !ok {
				return nil, ErrUnsafeManifest
			}
		}
	}
	return &Policy{allowed: requested}, nil
}

// Allows checks one already-resolved address, port and named method; it never
// resolves a hostname or follows a redirect. False is the default for a nil
// policy, noncanonical address family, unknown method or absent pair.
func (p *Policy) Allows(address netip.Addr, port uint16, method string) bool {
	if p == nil || !address.Is4() || port == 0 || !knownMethod(method) {
		return false
	}
	_, ok := p.allowed[endpoint{address: address, port: port}][method]
	return ok
}

func parse(document []byte) (manifest, error) {
	if !strictjson.ValidObject(document, maxDocumentBytes, 16) {
		return nil, ErrUnsafeManifest
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(document, &root) != nil || !exactKeys(root, "version", "targets") {
		return nil, ErrUnsafeManifest
	}
	var version int
	if json.Unmarshal(root["version"], &version) != nil || version != 1 {
		return nil, ErrUnsafeManifest
	}
	var targets []json.RawMessage
	if json.Unmarshal(root["targets"], &targets) != nil || len(targets) < 1 || len(targets) > maxTargets {
		return nil, ErrUnsafeManifest
	}
	result := make(manifest, len(targets))
	for _, raw := range targets {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || !exactKeys(fields, "address", "port", "methods") {
			return nil, ErrUnsafeManifest
		}
		var addressText string
		var port uint16
		var methods []string
		if json.Unmarshal(fields["address"], &addressText) != nil || json.Unmarshal(fields["port"], &port) != nil || port == 0 ||
			json.Unmarshal(fields["methods"], &methods) != nil || len(methods) < 1 || len(methods) > 3 {
			return nil, ErrUnsafeManifest
		}
		address, err := netip.ParseAddr(addressText)
		if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != addressText {
			return nil, ErrUnsafeManifest
		}
		ep := endpoint{address: address, port: port}
		if _, exists := result[ep]; exists {
			return nil, ErrUnsafeManifest
		}
		methodSet := make(map[string]struct{}, len(methods))
		for _, method := range methods {
			if !knownMethod(method) {
				return nil, ErrUnsafeManifest
			}
			if _, duplicate := methodSet[method]; duplicate {
				return nil, ErrUnsafeManifest
			}
			methodSet[method] = struct{}{}
		}
		result[ep] = methodSet
	}
	return result, nil
}

func exactKeys(object map[string]json.RawMessage, names ...string) bool {
	if len(object) != len(names) {
		return false
	}
	for _, name := range names {
		if _, exists := object[name]; !exists {
			return false
		}
	}
	return true
}

func knownMethod(method string) bool {
	switch method {
	case "tcp.connect", "http.request", "browser.navigate":
		return true
	default:
		return false
	}
}
