package backend

import "testing"

func TestRunningVersionFollowsVersion(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })

	Version = "v1.2.3"
	b := newBackend(credentialTypes[defaultCredentialType]())
	if b.RunningVersion != "v1.2.3" {
		t.Fatalf("RunningVersion = %q, want v1.2.3", b.RunningVersion)
	}
}
