package cmd

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/config"
	vaultlib "github.com/danieljustus/OpenPass/internal/vault"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func TestRunServeStdioStartsTransportWhenServiceVaultLocked(t *testing.T) {
	lockedErr := errors.New("vault locked")
	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.DefaultAgent = "hermes-runtime"
	cfg.Agents["hermes-runtime"] = config.AgentProfile{
		Name:         "hermes-runtime",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}
	if _, err := vaultlib.InitWithPassphrase(vaultDir, []byte("synthetic-locked-vault-passphrase"), cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	t.Setenv("OPENPASS_VAULT", vaultDir)
	t.Setenv("OPENPASS_PASSPHRASE", "")
	t.Setenv("OPENPASS_SERVICE_VAULT_PASSPHRASE", "")

	oldRunStdio := runStdioServerFunc
	oldUnlock := serveUnlockVault
	oldSessionExpired := sessionIsExpired
	oldNotify := serveSignalNotify
	t.Cleanup(func() {
		runStdioServerFunc = oldRunStdio
		serveUnlockVault = oldUnlock
		sessionIsExpired = oldSessionExpired
		serveSignalNotify = oldNotify
	})

	called := false
	runStdioServerFunc = func(ctx context.Context, v *vaultpkg.Vault, agentName string) error {
		_ = ctx
		called = true
		if v != nil {
			t.Fatalf("runServe passed an unlocked vault to locked service-mode stdio")
		}
		if agentName != "hermes-runtime" {
			t.Fatalf("agentName = %q, want hermes-runtime", agentName)
		}
		return nil
	}
	serveUnlockVault = func(vaultDir string, interactive bool) (*vaultpkg.Vault, error) {
		return nil, lockedErr
	}
	sessionIsExpired = func(string) bool { return true }
	serveSignalNotify = func(chan<- os.Signal, ...os.Signal) {}

	cmd := newServeTestCommand(t, "hermes-runtime", true)
	if err := runServe(cmd, nil); err != nil {
		t.Fatalf("runServe() error = %v, want nil so stdio transport can report structured locked-vault errors", err)
	}
	if !called {
		t.Fatal("runServe did not start stdio transport")
	}
}

func newServeTestCommand(t *testing.T, agent string, stdio bool) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "serve"}
	cmd.Flags().String("agent", "", "")
	cmd.Flags().Int("port", 8080, "")
	cmd.Flags().Bool("stdio", false, "")
	cmd.Flags().String("bind", "127.0.0.1", "")
	if err := cmd.Flags().Set("agent", agent); err != nil {
		t.Fatalf("set agent: %v", err)
	}
	if err := cmd.Flags().Set("stdio", strconv.FormatBool(stdio)); err != nil {
		t.Fatalf("set stdio: %v", err)
	}
	return cmd
}
