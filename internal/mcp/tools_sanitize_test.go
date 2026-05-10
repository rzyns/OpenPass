package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     true,
				ApprovalMode: "none",
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if srv == nil {
		t.Fatal("New() returned nil server")
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func TestHandleSanitizeOutput(t *testing.T) {
	server := setupTestServer(t)

	tests := []struct {
		name    string
		args    map[string]any
		wantErr bool
		check   func(t *testing.T, text string)
	}{
		{
			name: "sanitize AWS key",
			args: map[string]any{
				"text": "My AWS key is AKIAIOSFODNN7EXAMPLE",
			},
			wantErr: false,
			check: func(t *testing.T, text string) {
				if text == "" {
					t.Fatal("expected non-empty result")
				}
			},
		},
		{
			name:    "missing text",
			args:    map[string]any{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := CallToolRequest{Arguments: tt.args}
			result, err := server.handleSanitizeOutput(t.Context(), req)
			if tt.wantErr {
				if err == nil && (result == nil || !result.IsError) {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, result.Text)
			}
		})
	}
}

func TestHandleScanText(t *testing.T) {
	server := setupTestServer(t)
	secret := "ghp_" + strings.Repeat("E", 36)

	result, err := server.handleScanText(t.Context(), CallToolRequest{Arguments: map[string]any{
		"text": secret,
	}})
	if err != nil {
		t.Fatalf("handleScanText() error = %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("handleScanText() returned error result: %#v", result)
	}
	if strings.Contains(result.Text, secret) {
		t.Fatalf("scan_text leaked raw secret: %s", result.Text)
	}

	var report struct {
		FindingCount int `json:"finding_count"`
		Findings     []struct {
			DetectorName  string `json:"detector_name"`
			Severity      string `json:"severity"`
			RedactedValue string `json:"redacted_value"`
		} `json:"findings"`
		RedactedText string `json:"redacted_text"`
	}
	if err := json.Unmarshal([]byte(result.Text), &report); err != nil {
		t.Fatalf("scan_text returned invalid JSON: %v", err)
	}
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("got report %#v, want one finding", report)
	}
	if report.Findings[0].DetectorName != "github_pat" || report.Findings[0].Severity != "high" {
		t.Fatalf("unexpected finding metadata: %#v", report.Findings[0])
	}
	if report.RedactedText == "" || !strings.Contains(report.RedactedText, report.Findings[0].RedactedValue) {
		t.Fatalf("missing redacted text coherence: %#v", report)
	}
}

func TestHandleScanTextHonorsCustomMarker(t *testing.T) {
	server := setupTestServer(t)
	secret := "sk_live_" + strings.Repeat("F", 24)

	result, err := server.handleScanText(t.Context(), CallToolRequest{Arguments: map[string]any{
		"text":   secret,
		"marker": "[REDACTED-SENSITIVE-VALUE]",
	}})
	if err != nil {
		t.Fatalf("handleScanText() error = %v", err)
	}
	if strings.Contains(result.Text, secret) {
		t.Fatalf("scan_text leaked raw secret: %s", result.Text)
	}
	if !strings.Contains(result.Text, "[REDACTED-SENSITIVE-VALUE]") {
		t.Fatalf("custom marker missing from result: %s", result.Text)
	}
}

func TestSanitizeRunOutput(t *testing.T) {
	server := setupTestServer(t)

	stdout := "The secret is my-secret-value"
	stderr := "Error: my-secret-value"
	resolvedEnv := map[string]string{
		"SECRET": "my-secret-value",
	}

	sanitizedStdout, sanitizedStderr := server.sanitizeRunOutput(stdout, stderr, resolvedEnv)

	if sanitizedStdout != "The secret is ***" {
		t.Errorf("stdout = %q, want %q", sanitizedStdout, "The secret is ***")
	}
	if sanitizedStderr != "Error: ***" {
		t.Errorf("stderr = %q, want %q", sanitizedStderr, "Error: ***")
	}
}

func TestSanitizeRunOutputNoSecrets(t *testing.T) {
	server := setupTestServer(t)

	stdout := "Normal output without secrets"
	stderr := ""

	sanitizedStdout, sanitizedStderr := server.sanitizeRunOutput(stdout, stderr, nil)

	if sanitizedStdout != stdout {
		t.Errorf("stdout = %q, want %q", sanitizedStdout, stdout)
	}
	if sanitizedStderr != stderr {
		t.Errorf("stderr = %q, want %q", sanitizedStderr, stderr)
	}
}
