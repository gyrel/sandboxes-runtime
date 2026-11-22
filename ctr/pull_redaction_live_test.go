package ctr

// TestLivePullErrorRedaction verifies against a real, owned containerd that
// a failing pull reports no host filesystem paths. It pulls a non-resolvable
// tag only; it neither creates nor removes sandbox resources. Skipped unless
// RHEIC_TEST_CTR_SOCKET and RHEIC_TEST_CTR_BIN are supplied.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLivePullErrorRedaction(t *testing.T) {
	socket := os.Getenv("RHEIC_TEST_CTR_SOCKET")
	ctrBin := os.Getenv("RHEIC_TEST_CTR_BIN")
	if socket == "" || ctrBin == "" {
		t.Skip("live test; requires RHEIC_TEST_CTR_SOCKET and RHEIC_TEST_CTR_BIN for an owned daemon")
	}
	client, err := New(Config{Socket: socket, CTR: ctrBin})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	err = client.EnsureImage(ctx, "docker.io/library/rheic-does-not-exist-4f1a9c:latest")
	if err == nil {
		t.Fatal("expected pull failure")
	}
	message := err.Error()
	t.Logf("live error message: %s", message)
	home, _ := os.UserHomeDir()
	for _, leak := range []string{socket, ctrBin, home + "/"} {
		if leak != "" && strings.Contains(message, leak) {
			t.Fatalf("live error leaked %q: %s", leak, message)
		}
	}
	if !strings.Contains(message, "images pull") || !strings.Contains(message, "rheic-does-not-exist") {
		t.Fatalf("live error lost actionable context: %s", message)
	}
}
