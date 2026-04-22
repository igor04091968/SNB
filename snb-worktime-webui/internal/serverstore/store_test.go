package serverstore

import (
	"path/filepath"
	"testing"

	"snb-worktime-webui/internal/model"
)

func TestUpsertPreservesSecretsOnBlankUpdate(t *testing.T) {
	t.Parallel()

	store := New(filepath.Join(t.TempDir(), "linux_servers.json"))

	created, err := store.Upsert(model.LinuxServer{
		ID:                   "new_ats",
		Name:                 "new_ats",
		Host:                 "10.33.1.82",
		Port:                 22,
		Username:             "prog10",
		Password:             "04091968",
		PrivateKeyPEM:        "KEYDATA",
		PrivateKeyPassphrase: "PASSPHRASE",
		Notes:                "initial",
	})
	if err != nil {
		t.Fatalf("initial upsert failed: %v", err)
	}

	_, err = store.Upsert(model.LinuxServer{
		ID:       created.ID,
		Name:     created.Name,
		Host:     created.Host,
		Port:     created.Port,
		Username: created.Username,
		Notes:    "edited without re-entering secrets",
	})
	if err != nil {
		t.Fatalf("blank-secret upsert failed: %v", err)
	}

	servers, err := store.ByIDs([]string{created.ID})
	if err != nil {
		t.Fatalf("load after update failed: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected exactly one stored server, got %d", len(servers))
	}
	stored := servers[0]

	if stored.Password != "04091968" {
		t.Fatalf("password was not preserved, got %q", stored.Password)
	}
	if stored.PrivateKeyPEM != "KEYDATA" {
		t.Fatalf("private key was not preserved, got %q", stored.PrivateKeyPEM)
	}
	if stored.PrivateKeyPassphrase != "PASSPHRASE" {
		t.Fatalf("key passphrase was not preserved, got %q", stored.PrivateKeyPassphrase)
	}
}
