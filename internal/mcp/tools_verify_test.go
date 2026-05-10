package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func TestVerifyCredentialToolReturnsTypedStatusAndDoesNotLeakSecret(t *testing.T) {
	vaultDir, identity := mockVault(t)
	secret := "fake-valid-credential"
	entry := &vault.Entry{Data: map[string]any{"token": secret}}
	if err := vault.WriteEntry(vaultDir, "providers/fake/api-token", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"providers/fake"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	payload, err := srv.executeTool(context.Background(), "verify_credential", json.RawMessage(`{
		"path":"providers/fake/api-token",
		"field":"token",
		"provider":"fake"
	}`))
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	text := toolPayloadText(t, payload)
	if strings.Contains(text, secret) {
		t.Fatalf("verify_credential leaked secret in response: %s", text)
	}
	var result struct {
		Provider string `json:"provider"`
		Status   string `json:"status"`
		Path     string `json:"path"`
		Field    string `json:"field"`
	}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatalf("unmarshal result: %v; text=%s", err, text)
	}
	if result.Status != "valid" {
		t.Fatalf("status = %q, want valid", result.Status)
	}
	if result.Provider != "fake" {
		t.Fatalf("provider = %q, want fake", result.Provider)
	}
	if result.Path != "providers/fake/api-token" || result.Field != "token" {
		t.Fatalf("path/field = %q/%q, want providers/fake/api-token/token", result.Path, result.Field)
	}
}

func TestVerifyCredentialToolHonorsScopeBeforeReadingSecret(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{Data: map[string]any{"token": "valid"}}
	if err := vault.WriteEntry(vaultDir, "providers/fake/api-token", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"providers/other"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	_, err := srv.executeTool(context.Background(), "verify_credential", json.RawMessage(`{
		"path":"providers/fake/api-token",
		"field":"token",
		"provider":"fake"
	}`))
	if err == nil {
		t.Fatal("executeTool() expected scope error, got nil")
	}
	if strings.Contains(err.Error(), "valid") {
		t.Fatalf("scope error leaked secret: %v", err)
	}
}

func TestVerifyCredentialToolRequiresStringSecretField(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{Data: map[string]any{"token": 12345}}
	if err := vault.WriteEntry(vaultDir, "providers/fake/api-token", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"providers/fake"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	payload, err := srv.executeTool(context.Background(), "verify_credential", json.RawMessage(`{
		"path":"providers/fake/api-token",
		"field":"token",
		"provider":"fake"
	}`))
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
	if !payload["isError"].(bool) {
		t.Fatalf("expected tool error payload, got %#v", payload)
	}
	text := toolPayloadText(t, payload)
	if !strings.Contains(text, "field must contain a string credential value") {
		t.Fatalf("tool error text = %q", text)
	}
}

func toolPayloadText(t *testing.T, payload map[string]any) string {
	t.Helper()
	content, ok := payload["content"].([]map[string]any)
	if !ok || len(content) == 0 {
		t.Fatalf("payload content has unexpected shape: %#v", payload["content"])
	}
	text, ok := content[0]["text"].(string)
	if !ok {
		t.Fatalf("payload text has unexpected shape: %#v", content[0])
	}
	return text
}
