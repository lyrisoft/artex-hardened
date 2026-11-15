package securityprofile

import "testing"

func TestModeDefaultsAndAdvancedAcknowledgement(t *testing.T) {
    for _, tt := range []struct {
        name, profile, ack string
        want Mode
        mutate bool
    }{
        {"default", "", "", Pentest, false},
        {"pentest", "pentest", "", Pentest, false},
        {"research", "research", "", Research, false},
        {"invalid", "unsupported", "", Research, false},
        {"advanced-unacknowledged", "advanced-lab", "", Pentest, false},
        {"advanced-wrong-ack", "advanced-lab", "yes", Pentest, false},
        {"advanced-authorized", "advanced-lab", advancedAcknowledgement, AdvancedLab, true},
    } {
        t.Run(tt.name, func(t *testing.T) {
            t.Setenv("ARTEX_SECURITY_PROFILE", tt.profile)
            t.Setenv("ARTEX_ADVANCED_LAB_ACK", tt.ack)
            if got := Current(); got != tt.want { t.Fatalf("Current = %q, want %q", got, tt.want) }
            if got := AgentMayMutatePlatform(); got != tt.mutate { t.Fatalf("mutate = %v, want %v", got, tt.mutate) }
            if got := AgentMayRemoveAssets(); got != tt.mutate { t.Fatalf("remove = %v, want %v", got, tt.mutate) }
        })
    }
}
