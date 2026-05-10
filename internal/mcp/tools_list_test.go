package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func TestHandleList_WithPrefix(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"prefix": ""},
	}

	result, err := srv.handleList(context.Background(), req)
	if err != nil {
		t.Fatalf("handleList() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleList() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleList() returned error: %s", result.Text)
	}

	var entries []map[string]any
	if err := json.Unmarshal([]byte(result.Text), &entries); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected entries, got empty list")
	}

	found := false
	for _, entry := range entries {
		if entry["path"] == "github" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'github' in entries, got %v", entries)
	}
}

func TestHandleList_WithDetailsDisabled(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"prefix": "", "include_details": "false"},
	}

	result, err := srv.handleList(context.Background(), req)
	if err != nil {
		t.Fatalf("handleList() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleList() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleList() returned error: %s", result.Text)
	}

	var entries []string
	if err := json.Unmarshal([]byte(result.Text), &entries); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected entries, got empty list")
	}
}

func TestExecuteTool_ListEntries(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args := json.RawMessage(`{"prefix": ""}`)
	result, err := srv.executeTool(context.Background(), "list_entries", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}
	text, ok := content[0]["text"].(string)
	if !ok {
		t.Fatal("content text has unexpected type")
	}
	if !strings.Contains(text, "github") {
		t.Errorf("expected 'github' in result, got %s", text)
	}
}

func TestHandleList_OutsideScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"prefix": ""},
	}

	_, err := srv.handleList(context.Background(), req)
	if err == nil {
		t.Fatal("handleList() expected error for out-of-scope path, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("handleList() error = %v, want 'outside allowed scope'", err)
	}
}

func TestHandleList_FiltersExpiringAndStaleMetadataWithoutValues(t *testing.T) {
	vaultDir, identity := mockVault(t)
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)

	writeLifecycleEntry := func(path string, meta vault.SecretMetadata) {
		t.Helper()
		entry := &vault.Entry{
			Data:           map[string]any{"password": "secret-value-for-" + path},
			SecretMetadata: meta,
		}
		if err := vault.WriteEntry(vaultDir, path, entry, identity); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	expiresSoon := now.Add(12 * time.Hour)
	expiresLater := now.Add(48 * time.Hour)
	lastRotated := now.Add(-10 * 24 * time.Hour)
	writeLifecycleEntry("agent/b-expiring-later", vault.SecretMetadata{ExpiresAt: &expiresLater})
	writeLifecycleEntry("agent/a-expiring-soon", vault.SecretMetadata{ExpiresAt: &expiresSoon})
	writeLifecycleEntry("agent/c-stale", vault.SecretMetadata{LastRotatedAt: &lastRotated, RotationInterval: "7d"})
	writeLifecycleEntry("agent/d-invalid", vault.SecretMetadata{LastRotatedAt: &lastRotated, RotationInterval: "not-a-duration"})

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.now = func() time.Time { return now }

	result, err := srv.handleList(context.Background(), CallToolRequest{
		Arguments: map[string]any{
			"prefix":          "agent/",
			"expiring_within": "72h",
			"stale_after":     "7d",
		},
	})
	if err != nil {
		t.Fatalf("handleList() error = %v", err)
	}
	if strings.Contains(result.Text, "secret-value-for-") {
		t.Fatalf("list response leaked secret value: %s", result.Text)
	}

	var entries []map[string]any
	if err := json.Unmarshal([]byte(result.Text), &entries); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("entries len = %d, want 4: %#v", len(entries), entries)
	}
	wantOrder := []string{"agent/c-stale", "agent/a-expiring-soon", "agent/b-expiring-later", "agent/d-invalid"}
	for i, want := range wantOrder {
		if entries[i]["path"] != want {
			t.Fatalf("entry[%d] path = %v, want %s; entries=%#v", i, entries[i]["path"], want, entries)
		}
	}
	if entries[1]["expires_at"] != "2026-05-11T00:00:00Z" {
		t.Fatalf("expires_at = %v, want RFC3339 timestamp", entries[1]["expires_at"])
	}
	if entries[0]["rotation_stale"] != true {
		t.Fatalf("rotation_stale for stale entry = %v, want true", entries[0]["rotation_stale"])
	}
	if entries[3]["metadata_error"] == nil {
		t.Fatalf("invalid rotation interval should be surfaced, got %#v", entries[3])
	}
}
