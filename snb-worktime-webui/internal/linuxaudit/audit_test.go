package linuxaudit

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
