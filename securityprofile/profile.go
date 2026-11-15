// Package securityprofile enforces the local operator's autonomy profile.
// It is not a sandbox, filesystem boundary, or destination-level firewall.
package securityprofile

import (
    "os"
    "strings"
)

type Mode string

const (
    Research Mode = "research"
    Pentest Mode = "pentest"
    AdvancedLab Mode = "advanced-lab"
    advancedAcknowledgement = "I_UNDERSTAND_ISOLATED_LAB_ONLY"
)

// Current intentionally falls back to the least expansive profile on invalid
// configuration. Advanced mode requires two independent settings.
func Current() Mode {
    switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_SECURITY_PROFILE"))) {
    case "", "pentest":
        return Pentest
    case "research":
        return Research
    case "advanced-lab":
        if os.Getenv("ARTEX_ADVANCED_LAB_ACK") == advancedAcknowledgement {
            return AdvancedLab
        }
        return Pentest
    default:
        return Research
    }
}

// AgentMayMutatePlatform gates agent-driven installation of executable tools,
// remote MCP servers, and rewrites to the skill scripts. It deliberately does
// not disable Bash, Nmap, browsers or other authorized pentest functionality.
// Administrators may still manage these features through the protected UI.
func AgentMayMutatePlatform() bool {
    return Current() == AdvancedLab
}

// AgentMayRemoveAssets is intentionally restricted in default pentest mode.
func AgentMayRemoveAssets() bool {
    return Current() == AdvancedLab
}
