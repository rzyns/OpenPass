package mcp

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/policy"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func TestServiceRuntimeListsToolsAndReturnsStructuredLockedToolError(t *testing.T) {
	secret := "synthetic-service-passphrase-do-not-leak"
	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.DefaultAgent = "hermes-runtime"
	cfg.Agents["hermes-runtime"] = config.AgentProfile{
		Name:            "hermes-runtime",
		AllowedPaths:    []string{"*"},
		CanWrite:        true,
		CanRunCommands:  true,
		CanManageConfig: true,
		ApprovalMode:    "none",
	}
	if _, err := vault.InitWithPassphrase(vaultDir, []byte(secret), cfg); err != nil {
		t.Fatalf("init service vault: %v", err)
	}

	srv, err := NewServiceRuntimeServer(vaultDir, "hermes-runtime", "stdio", func(context.Context) (*vault.Vault, error) {
		return nil, NewServiceVaultError(CodeMissingBootstrap, "service vault unlock material is unavailable", &ServiceVaultErrorContext{
			Providers: []string{"session", "env"},
		})
	})
	if err != nil {
		t.Fatalf("NewServiceRuntimeServer() error = %v", err)
	}
	handler := NewProtocolHandler("openpass", "1.0.0", srv)

	initResp, err := handler.HandleMessage(context.Background(), &Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize", Params: mustRawJSON(t, map[string]any{
		"protocolVersion": LatestSupportedProtocolVersion,
		"clientInfo":      map[string]any{"name": "test", "version": "dev"},
	})})
	if err != nil || initResp.Error != nil {
		t.Fatalf("initialize response = %#v, err = %v", initResp, err)
	}

	listResp, err := handler.HandleMessage(context.Background(), &Message{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "tools/list"})
	if err != nil || listResp.Error != nil {
		t.Fatalf("tools/list response = %#v, err = %v", listResp, err)
	}
	listBody := mustMarshalString(t, listResp.Result)
	if !strings.Contains(listBody, "health") || !strings.Contains(listBody, "list_entries") {
		t.Fatalf("tools/list missing expected tools: %s", listBody)
	}

	callResp, err := handler.HandleMessage(context.Background(), &Message{JSONRPC: "2.0", ID: json.RawMessage(`3`), Method: "tools/call", Params: mustRawJSON(t, map[string]any{
		"name":      "list_entries",
		"arguments": map[string]any{"prefix": ""},
	})})
	if err != nil || callResp.Error != nil {
		t.Fatalf("tools/call returned protocol error response = %#v, err = %v", callResp, err)
	}
	callBody := mustMarshalString(t, callResp.Result)
	if !strings.Contains(callBody, `"isError":true`) || !strings.Contains(callBody, string(CodeMissingBootstrap)) {
		t.Fatalf("tools/call result = %s, want isError with %s", callBody, CodeMissingBootstrap)
	}
	if strings.Contains(callBody, secret) {
		t.Fatalf("tools/call leaked synthetic passphrase: %s", callBody)
	}
}

func TestServiceRuntimeScanTextDoesNotUnlockVault(t *testing.T) {
	secret := "synthetic-scan-no-unlock-passphrase-do-not-leak"
	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.DefaultAgent = "hermes-runtime"
	cfg.Agents["hermes-runtime"] = config.AgentProfile{
		Name:         "hermes-runtime",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}
	if _, err := vault.InitWithPassphrase(vaultDir, []byte(secret), cfg); err != nil {
		t.Fatalf("init service vault: %v", err)
	}

	unlockAttempts := 0
	srv, err := NewServiceRuntimeServer(vaultDir, "hermes-runtime", "stdio", func(context.Context) (*vault.Vault, error) {
		unlockAttempts++
		return nil, NewServiceVaultError(CodeMissingBootstrap, "service vault unlock material is unavailable", nil)
	})
	if err != nil {
		t.Fatalf("NewServiceRuntimeServer() error = %v", err)
	}
	handler := NewProtocolHandler("openpass", "1.0.0", srv)
	_, _ = handler.HandleMessage(context.Background(), &Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize", Params: mustRawJSON(t, map[string]any{
		"protocolVersion": LatestSupportedProtocolVersion,
		"clientInfo":      map[string]any{"name": "test", "version": "dev"},
	})})

	scanSecret := "ghp_" + strings.Repeat("E", 36)
	resp, err := handler.HandleMessage(context.Background(), &Message{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "tools/call", Params: mustRawJSON(t, map[string]any{
		"name":      "scan_text",
		"arguments": map[string]any{"text": scanSecret},
	})})
	if err != nil || resp.Error != nil {
		t.Fatalf("scan_text response = %#v, err = %v", resp, err)
	}
	body := mustMarshalString(t, resp.Result)
	if strings.Contains(body, `"isError":true`) || strings.Contains(body, string(CodeMissingBootstrap)) {
		t.Fatalf("scan_text should succeed without vault unlock, got: %s", body)
	}
	if strings.Contains(body, scanSecret) || strings.Contains(body, secret) {
		t.Fatalf("scan_text leaked secret material: %s", body)
	}
	if unlockAttempts != 0 {
		t.Fatalf("scan_text attempted %d vault unlock(s), want 0", unlockAttempts)
	}
}

func TestServiceRuntimePolicyDenialPrecedesLazyUnlock(t *testing.T) {
	secret := "synthetic-policy-order-passphrase-do-not-leak"
	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.DefaultAgent = "hermes-runtime"
	cfg.Agents["hermes-runtime"] = config.AgentProfile{
		Name:         "hermes-runtime",
		AllowedPaths: []string{"*"},
		ApprovalMode: "none",
	}
	if _, err := vault.InitWithPassphrase(vaultDir, []byte(secret), cfg); err != nil {
		t.Fatalf("init service vault: %v", err)
	}

	unlockAttempts := 0
	srv, err := NewServiceRuntimeServer(vaultDir, "hermes-runtime", "stdio", func(context.Context) (*vault.Vault, error) {
		unlockAttempts++
		return nil, NewServiceVaultError(CodeMissingBootstrap, "service vault unlock material is unavailable", nil)
	})
	if err != nil {
		t.Fatalf("NewServiceRuntimeServer() error = %v", err)
	}
	srv.policyEngine = policy.NewEngine([]*policy.Policy{{Version: "1", Rules: []policy.Rule{{
		Name:       "deny-blocked-paths",
		Conditions: policy.Conditions{Path: "blocked/**", ActionType: "get"},
		Action:     policy.ActionDeny,
	}}}})

	_, err = srv.executeTool(context.Background(), "get_entry", mustRawJSON(t, map[string]any{"path": "blocked/example"}))
	if err == nil || !strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("executeTool error = %v, want policy denial", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("policy error leaked synthetic passphrase: %v", err)
	}
	if unlockAttempts != 0 {
		t.Fatalf("policy-denied path attempted %d vault unlock(s), want 0", unlockAttempts)
	}
}

func TestServiceRuntimeUnlocksLazilyFromEnvironmentProvider(t *testing.T) {
	assertServiceRuntimeUnlocksLazilyFromEnv(t, "OPENPASS_SERVICE_VAULT_PASSPHRASE")
}

func TestServiceRuntimeUnlocksLazilyFromLegacyOpenPassPassphrase(t *testing.T) {
	assertServiceRuntimeUnlocksLazilyFromEnv(t, "OPENPASS_PASSPHRASE")
}

func assertServiceRuntimeUnlocksLazilyFromEnv(t *testing.T, envName string) {
	t.Helper()
	secret := "synthetic-env-service-passphrase-do-not-leak"
	vaultDir := t.TempDir()
	cfg := config.Default()
	cfg.DefaultAgent = "hermes-runtime"
	cfg.Agents["hermes-runtime"] = config.AgentProfile{
		Name:         "hermes-runtime",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}
	if _, err := vault.InitWithPassphrase(vaultDir, []byte(secret), cfg); err != nil {
		t.Fatalf("init service vault: %v", err)
	}
	t.Setenv(envName, secret)
	srv, err := NewServiceRuntimeServer(vaultDir, "hermes-runtime", "stdio", NewEnvironmentServiceUnlocker(vaultDir))
	if err != nil {
		t.Fatalf("NewServiceRuntimeServer() error = %v", err)
	}
	handler := NewProtocolHandler("openpass", "1.0.0", srv)
	_, _ = handler.HandleMessage(context.Background(), &Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize", Params: mustRawJSON(t, map[string]any{
		"protocolVersion": LatestSupportedProtocolVersion,
		"clientInfo":      map[string]any{"name": "test", "version": "dev"},
	})})

	resp, err := handler.HandleMessage(context.Background(), &Message{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "tools/call", Params: mustRawJSON(t, map[string]any{
		"name":      "get_auth_status",
		"arguments": map[string]any{},
	})})
	if err != nil || resp.Error != nil {
		t.Fatalf("get_auth_status response = %#v, err = %v", resp, err)
	}
	if srv.vault != nil {
		t.Fatal("get_auth_status should not unlock the vault")
	}

	resp, err = handler.HandleMessage(context.Background(), &Message{JSONRPC: "2.0", ID: json.RawMessage(`3`), Method: "tools/call", Params: mustRawJSON(t, map[string]any{
		"name":      "list_entries",
		"arguments": map[string]any{"prefix": ""},
	})})
	if err != nil || resp.Error != nil {
		t.Fatalf("list_entries response = %#v, err = %v", resp, err)
	}
	body := mustMarshalString(t, resp.Result)
	if strings.Contains(body, secret) {
		t.Fatalf("list_entries leaked synthetic passphrase: %s", body)
	}
	if strings.Contains(body, `"isError":true`) {
		t.Fatalf("list_entries failed after %s unlock: %s", envName, body)
	}
	if got := os.Getenv(envName); got != "" {
		t.Fatalf("%s was not cleared after unlock", envName)
	}
}

func mustRawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return b
}

func mustMarshalString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	return string(b)
}
