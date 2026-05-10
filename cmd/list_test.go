package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestCmdList_Empty(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "list")
	_ = out
}

func TestCmdList_Prefix(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	e := &vaultpkg.Entry{Data: map[string]any{"password": "p"}}
	_ = vaultpkg.WriteEntry(vaultDir, "work/aws", e, identity.Identity)
	_ = vaultpkg.WriteEntry(vaultDir, "personal/bank", e, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "list", "work/")
	if !strings.Contains(out, "work/aws") {
		t.Errorf("expected work/aws in output, got: %s", out)
	}
	if strings.Contains(out, "personal") {
		t.Errorf("unexpected personal in prefix-filtered output: %s", out)
	}
}

func TestCmdList_Alias(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "p"}}
	_ = vaultpkg.WriteEntry(vaultDir, "ls-entry", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "ls")
	if !strings.Contains(out, "ls-entry") {
		t.Errorf("expected ls-entry in output, got: %s", out)
	}
}

func TestCmdList_Uninitialized(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "list"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "vault not initialized") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected vault not initialized, got: %s", stderr)
	}
}

func TestList_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	t.Run("uninitialized vault", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("OPENPASS_VAULT", tmpDir)
		defer func() { _ = os.Unsetenv("OPENPASS_VAULT") }()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "list"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Errorf("expected 'not initialized' error, got: %v", err)
		}
	})
}

func TestCmdList_JSONFiltersLifecycleMetadataWithoutValues(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	now := time.Now().UTC().Truncate(time.Second)
	expiresSoon := now.Add(2 * time.Hour)
	expiresLater := now.Add(48 * time.Hour)
	lastRotated := now.Add(-10 * 24 * time.Hour)

	writeEntry := func(path string, meta vaultpkg.SecretMetadata) {
		t.Helper()
		entry := &vaultpkg.Entry{Data: map[string]any{"password": "secret-value-for-" + path}, SecretMetadata: meta}
		if err := vaultpkg.WriteEntry(vaultDir, path, entry, identity.Identity); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	writeEntry("agent/expiring-soon", vaultpkg.SecretMetadata{ExpiresAt: &expiresSoon})
	writeEntry("agent/expiring-later", vaultpkg.SecretMetadata{ExpiresAt: &expiresLater})
	writeEntry("agent/stale", vaultpkg.SecretMetadata{LastRotatedAt: &lastRotated, RotationInterval: "7d"})
	writeEntry("agent/current", vaultpkg.SecretMetadata{})

	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "--output", "json", "list", "agent/", "--expiring-within", "72h", "--stale-after", "7d")
	if strings.Contains(out, "secret-value-for-") {
		t.Fatalf("list JSON leaked secret value: %s", out)
	}

	var entries []map[string]any
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("parse JSON output: %v\n%s", err, out)
	}
	if len(entries) != 3 {
		t.Fatalf("entries len = %d, want 3: %#v", len(entries), entries)
	}
	if entries[0]["path"] != "agent/stale" || entries[0]["rotation_stale"] != true {
		t.Fatalf("first entry = %#v, want stale rotation first", entries[0])
	}
	if entries[1]["path"] != "agent/expiring-soon" || entries[1]["expiring"] != true {
		t.Fatalf("second entry = %#v, want expiring soon", entries[1])
	}
	if entries[2]["path"] != "agent/expiring-later" || entries[2]["expiring"] != true {
		t.Fatalf("third entry = %#v, want expiring later", entries[2])
	}
}

func TestCmdList_TextFiltersLifecycleMetadata(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	now := time.Now().UTC().Truncate(time.Second)
	expiresSoon := now.Add(2 * time.Hour)
	expiresLate := now.Add(96 * time.Hour)

	soon := &vaultpkg.Entry{Data: map[string]any{"password": "secret-value-soon"}, SecretMetadata: vaultpkg.SecretMetadata{ExpiresAt: &expiresSoon}}
	late := &vaultpkg.Entry{Data: map[string]any{"password": "secret-value-late"}, SecretMetadata: vaultpkg.SecretMetadata{ExpiresAt: &expiresLate}}
	if err := vaultpkg.WriteEntry(vaultDir, "agent/text-soon", soon, identity.Identity); err != nil {
		t.Fatalf("write soon: %v", err)
	}
	if err := vaultpkg.WriteEntry(vaultDir, "agent/text-late", late, identity.Identity); err != nil {
		t.Fatalf("write late: %v", err)
	}

	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "list", "agent/", "--expiring-within", "72h")
	if !strings.Contains(out, "agent/text-soon") {
		t.Fatalf("expected expiring entry in text output, got: %s", out)
	}
	if strings.Contains(out, "agent/text-late") {
		t.Fatalf("did not expect late entry in text output: %s", out)
	}
	if strings.Contains(out, "secret-value-") {
		t.Fatalf("text list leaked secret value: %s", out)
	}
}
