package syntheticpolicy

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const valid = `{"version":1,"targets":[{"address":"172.30.137.20","port":443,"methods":["tcp.connect","http.request"]}]}`

func TestManifestRejectsAmbiguityAndBroadTargets(t *testing.T) {
	if err := Validate([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, document := range map[string]string{
		"duplicate root":       `{"version":1,"version":1,"targets":[]}`,
		"escaped duplicate":    `{"version":1,"\u0076ersion":1,"targets":[]}`,
		"case variant":         `{"Version":1,"targets":[{"address":"172.30.137.20","port":443,"methods":["tcp.connect"]}]}`,
		"unknown root":         `{"version":1,"targets":[],"debug":true}`,
		"unknown target field": `{"version":1,"targets":[{"address":"172.30.137.20","port":443,"methods":["tcp.connect"],"extra":true}]}`,
		"unpaired surrogate":   `{"version":1,"targets":[{"address":"172.30.137.20","port":443,"methods":["\ud800"]}]}`,
		"unknown version":      strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"missing version":      strings.Replace(valid, `"version":1,`, ``, 1),
		"empty targets":        `{"version":1,"targets":[]}`,
		"null targets":         `{"version":1,"targets":null}`,
		"hostname":             strings.Replace(valid, "172.30.137.20", "synthetic.invalid", 1),
		"cidr":                 strings.Replace(valid, "172.30.137.20", "172.30.137.0/24", 1),
		"wildcard":             strings.Replace(valid, "172.30.137.20", "*", 1),
		"public IP":            strings.Replace(valid, "172.30.137.20", "8.8.8.8", 1),
		"loopback":             strings.Replace(valid, "172.30.137.20", "127.0.0.1", 1),
		"metadata IP":          strings.Replace(valid, "172.30.137.20", "169.254.169.254", 1),
		"IPv6":                 strings.Replace(valid, "172.30.137.20", "fd42::20", 1),
		"mapped IPv6":          strings.Replace(valid, "172.30.137.20", "::ffff:172.30.137.20", 1),
		"noncanonical IP":      strings.Replace(valid, "172.30.137.20", "172.030.137.20", 1),
		"zero port":            strings.Replace(valid, `"port":443`, `"port":0`, 1),
		"negative port":        strings.Replace(valid, `"port":443`, `"port":-1`, 1),
		"large port":           strings.Replace(valid, `"port":443`, `"port":65536`, 1),
		"fractional port":      strings.Replace(valid, `"port":443`, `"port":443.0`, 1),
		"empty methods":        strings.Replace(valid, `["tcp.connect","http.request"]`, `[]`, 1),
		"unknown method":       strings.Replace(valid, "http.request", "shell.anything", 1),
		"duplicate method":     strings.Replace(valid, "http.request", "tcp.connect", 1),
		"duplicate endpoint":   `{"version":1,"targets":[{"address":"10.0.0.1","port":80,"methods":["tcp.connect"]},{"address":"10.0.0.1","port":80,"methods":["http.request"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate([]byte(document)); err == nil {
				t.Fatal("unsafe manifest accepted")
			}
		})
	}
	var entries []string
	for i := 1; i <= maxTargets+1; i++ {
		entries = append(entries, fmt.Sprintf(`{"address":"10.0.0.%d","port":80,"methods":["tcp.connect"]}`, i))
	}
	if Validate([]byte(`{"version":1,"targets":[`+strings.Join(entries, ",")+`]}`)) == nil {
		t.Fatal("unbounded target list accepted")
	}
}

func TestPolicyRequiresExactApprovedInventoryIntersection(t *testing.T) {
	inventory := `{"version":1,"targets":[{"address":"172.30.137.20","port":443,"methods":["tcp.connect","http.request","browser.navigate"]},{"address":"172.30.137.21","port":80,"methods":["tcp.connect"]}]}`
	p, err := Compile([]byte(valid), sha256.Sum256([]byte(valid)), []byte(inventory))
	if err != nil {
		t.Fatal(err)
	}
	allowed := netip.MustParseAddr("172.30.137.20")
	for _, tc := range []struct {
		address netip.Addr
		port    uint16
		method  string
		want    bool
	}{
		{allowed, 443, "tcp.connect", true}, {allowed, 443, "http.request", true},
		{allowed, 443, "browser.navigate", false}, {allowed, 80, "tcp.connect", false},
		{netip.MustParseAddr("172.30.137.21"), 80, "tcp.connect", false},
		{netip.MustParseAddr("::ffff:172.30.137.20"), 443, "tcp.connect", false},
		{allowed, 443, "unknown", false},
	} {
		if got := p.Allows(tc.address, tc.port, tc.method); got != tc.want {
			t.Errorf("Allows(%s,%d,%s)=%v want %v", tc.address, tc.port, tc.method, got, tc.want)
		}
	}
	if (*Policy)(nil).Allows(allowed, 443, "tcp.connect") {
		t.Fatal("nil policy allowed a connection")
	}
	for _, requested := range []string{
		strings.Replace(valid, "172.30.137.20", "172.30.137.22", 1),
		strings.Replace(valid, `"port":443`, `"port":444`, 1),
		strings.Replace(valid, "http.request", "browser.navigate", 1),
	} {
		if _, err := Compile([]byte(requested), sha256.Sum256([]byte(requested)), []byte(valid)); err == nil {
			t.Fatal("scope exceeding independent inventory accepted")
		}
	}
	if _, err := Compile([]byte(valid), sha256.Sum256([]byte(valid)), []byte(`{}`)); err == nil {
		t.Fatal("invalid independent inventory accepted")
	}
	if _, err := Compile([]byte(valid), sha256.Sum256([]byte("different approved bytes")), []byte(inventory)); err == nil {
		t.Fatal("scope bytes did not match the approval digest")
	}
	approvedBytes, inventoryBytes := []byte(valid), []byte(inventory)
	immutable, err := Compile(approvedBytes, sha256.Sum256(approvedBytes), inventoryBytes)
	if err != nil {
		t.Fatal(err)
	}
	for i := range approvedBytes {
		approvedBytes[i] = 'x'
	}
	for i := range inventoryBytes {
		inventoryBytes[i] = 'x'
	}
	if !immutable.Allows(allowed, 443, "tcp.connect") {
		t.Fatal("caller mutation altered a compiled comparison")
	}
}

func FuzzManifestNeverExpandsInventory(f *testing.F) {
	f.Add([]byte(valid))
	f.Add([]byte(`{"version":1,"targets":[]}`))
	f.Fuzz(func(t *testing.T, document []byte) {
		p, err := Compile(document, sha256.Sum256(document), []byte(valid))
		if err != nil {
			return
		}
		if p.Allows(netip.MustParseAddr("172.30.137.21"), 443, "tcp.connect") ||
			p.Allows(netip.MustParseAddr("172.30.137.20"), 80, "tcp.connect") ||
			p.Allows(netip.MustParseAddr("172.30.137.20"), 443, "browser.navigate") {
			t.Fatal("compiled policy expanded independent inventory")
		}
	})
}
