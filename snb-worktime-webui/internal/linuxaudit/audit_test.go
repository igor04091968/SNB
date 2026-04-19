package linuxaudit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestBuildCommandWindowsClustersNearbyCommands(t *testing.T) {
	events := []commandEvent{
		{User: "igor", At: time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC), Source: "bash_history"},
		{User: "igor", At: time.Date(2026, 4, 19, 9, 8, 0, 0, time.UTC), Source: "bash_history"},
		{User: "igor", At: time.Date(2026, 4, 19, 9, 40, 0, 0, time.UTC), Source: "zsh_history"},
	}

	windows := buildCommandWindows(events)
	if len(windows) != 2 {
		t.Fatalf("expected 2 command windows, got %d: %+v", len(windows), windows)
	}
	if !windows[0].Started.Equal(time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC)) || !windows[0].Ended.Equal(time.Date(2026, 4, 19, 9, 9, 0, 0, time.UTC)) {
		t.Fatalf("unexpected first window: %+v", windows[0])
	}
}

func TestIntersectSessionWindowsRestrictsCommandActivityToSessions(t *testing.T) {
	commandWindows := []sessionWindow{
		{User: "igor", Started: time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC), Ended: time.Date(2026, 4, 19, 9, 20, 0, 0, time.UTC), Source: "bash_history"},
	}
	sessions := []sessionWindow{
		{User: "igor", Started: time.Date(2026, 4, 19, 9, 10, 0, 0, time.UTC), Ended: time.Date(2026, 4, 19, 9, 30, 0, 0, time.UTC), Source: "who"},
	}

	intersections := intersectSessionWindows(commandWindows, sessions)
	if len(intersections) != 1 {
		t.Fatalf("expected 1 intersection, got %d: %+v", len(intersections), intersections)
	}
	if !intersections[0].Started.Equal(time.Date(2026, 4, 19, 9, 10, 0, 0, time.UTC)) || !intersections[0].Ended.Equal(time.Date(2026, 4, 19, 9, 20, 0, 0, time.UTC)) {
		t.Fatalf("unexpected intersection: %+v", intersections[0])
	}
}

func TestFilterEventsWithinSessionsDropsUnconfirmedEvents(t *testing.T) {
	events := []commandEvent{
		{User: "igor", At: time.Date(2026, 4, 19, 8, 59, 0, 0, time.UTC), Source: "bash_history", Command: "ls", Category: actionCategoryShell},
		{User: "igor", At: time.Date(2026, 4, 19, 9, 5, 0, 0, time.UTC), Source: "bash_history", Command: "git status", Category: actionCategoryCoding},
	}
	sessions := []sessionWindow{
		{User: "igor", Started: time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC), Ended: time.Date(2026, 4, 19, 9, 30, 0, 0, time.UTC), Source: "who"},
	}

	filtered := filterEventsWithinSessions(events, sessions)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 confirmed event, got %d: %+v", len(filtered), filtered)
	}
	if filtered[0].Command != "git status" {
		t.Fatalf("unexpected confirmed event: %+v", filtered[0])
	}
}

func TestHostKeyCallbackAcceptsAndPersistsNewKey(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "known_hosts")
	callback, err := hostKeyCallback(keyPath)
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}

	firstKey := mustPublicKey(t)
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if err := callback("[127.0.0.1]:22", addr, firstKey); err != nil {
		t.Fatalf("callback(new key) error = %v", err)
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("known_hosts file is empty after accepting new key")
	}

	reloaded, err := hostKeyCallback(keyPath)
	if err != nil {
		t.Fatalf("hostKeyCallback(reload) error = %v", err)
	}
	if err := reloaded("[127.0.0.1]:22", addr, firstKey); err != nil {
		t.Fatalf("callback(known key) error = %v", err)
	}
}

func TestHostKeyCallbackRejectsChangedKey(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "known_hosts")
	callback, err := hostKeyCallback(keyPath)
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if err := callback("[127.0.0.1]:22", addr, mustPublicKey(t)); err != nil {
		t.Fatalf("callback(seed key) error = %v", err)
	}
	if err := callback("[127.0.0.1]:22", addr, mustPublicKey(t)); err == nil {
		t.Fatal("callback(changed key) unexpectedly succeeded")
	}
}

func mustPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	return signer.PublicKey()
}

func TestLocalPrivateKeySignersLoadsUserKey(t *testing.T) {
	homeDir := t.TempDir()
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	pemKey := mustPEMPrivateKey(t)
	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, pemKey, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	t.Setenv("HOME", homeDir)
	signers := localPrivateKeySigners()
	if len(signers) != 1 {
		t.Fatalf("localPrivateKeySigners() loaded %d signers, want 1", len(signers))
	}
}

func mustPEMPrivateKey(t *testing.T) []byte {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}
