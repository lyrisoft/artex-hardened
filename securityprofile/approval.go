package securityprofile

import (
	"encoding/json"
	"regexp"
	"strings"
)

// HighImpactToolCall evaluates a narrow, high-confidence set of destructive or
// privilege-changing commands. Matching these commands requires manual approval,
// irrespective of normal interception rules. This is NOT a sandbox: encoded
// scripts or other interpreters can evade text inspection. The independent
// container firewall is the actual destination protection.
func HighImpactToolCall(tool string, raw []byte) (string, bool) {
	if tool != "Bash" && tool != "shell_open" && tool != "shell_send" {
		return "", false
	}
	var v struct {
		Command string `json:"command"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "unparseable shell command", true // fail closed
	}
	s := v.Command
	if tool == "shell_send" { s = v.Text }
	s = strings.TrimSpace(s)
	if s == "" { return "", false }
	for _, p := range highImpactPatterns {
		if p.re.MatchString(s) { return p.reason, true }
	}
	return "", false
}

var highImpactPatterns = []struct {
	re *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]{0,400}\|\s*(?:sh|bash|zsh)\b`), "download-and-execute command"},
	{regexp.MustCompile(`(?i)\b(?:crontab|useradd|usermod|passwd|systemctl\s+enable)\b`), "potential persistence or account modification"},
	{regexp.MustCompile(`(?i)\b(?:iptables|ip6tables|nft)\s+(?:-F|--flush|flush)\b`), "firewall modification"},
	{regexp.MustCompile(`(?i)\b(?:mkfs(?:\.[a-z0-9]+)?|wipefs)\b`), "disk formatting or filesystem destruction"},
	{regexp.MustCompile(`(?i)\bdd\b[^\n]{0,300}\bof\s*=\s*/dev/\S+`), "disk device overwrite"},
}
