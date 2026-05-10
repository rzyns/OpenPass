package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/danieljustus/OpenPass/internal/credentialverify"
	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

const defaultCredentialVerificationField = "password"

type credentialVerificationResponse struct {
	Provider  string                  `json:"provider"`
	Status    credentialverify.Status `json:"status"`
	Path      string                  `json:"path"`
	Field     string                  `json:"field"`
	CheckedAt string                  `json:"checked_at"`
	Message   string                  `json:"message,omitempty"`
}

func (s *Server) handleVerifyCredential(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		s.logAudit(ctx, "verify_credential", "<invalid>", false)
		return NewToolResultError(err.Error()), nil
	}
	providerName, err := req.RequireString("provider")
	if err != nil {
		s.logAudit(ctx, "verify_credential", path, false)
		return NewToolResultError(err.Error()), nil
	}
	field := strings.TrimSpace(req.GetString("field", defaultCredentialVerificationField))
	if field == "" {
		field = defaultCredentialVerificationField
	}

	if !s.checkScope(path) {
		s.logAudit(ctx, "verify_credential", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	svc := vaultsvc.New(slog.Default(), s.vault)
	entry, err := svc.GetEntry(path)
	if err != nil {
		s.logAudit(ctx, "verify_credential", path, false)
		metrics.RecordVaultOperation("read", "error")
		return vaultServiceErrorResult(err)
	}
	value, ok := entry.Data[field]
	if !ok {
		s.logAudit(ctx, "verify_credential", path, false)
		return NewToolResultError("credential field not found"), nil
	}
	secret, ok := value.(string)
	if !ok {
		s.logAudit(ctx, "verify_credential", path, false)
		return NewToolResultError("credential field must contain a string credential value"), nil
	}

	verification := credentialverify.NewRegistry().Verify(ctx, credentialverify.Request{Provider: providerName, Secret: secret})
	s.logAudit(ctx, "verify_credential", path, verification.Status == credentialverify.StatusValid)
	metrics.RecordVaultOperation("read", "success")

	response := credentialVerificationResponse{
		Provider:  verification.Provider,
		Status:    verification.Status,
		Path:      path,
		Field:     field,
		CheckedAt: verification.CheckedAt.Format("2006-01-02T15:04:05Z07:00"),
		Message:   verification.Message,
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(payload)), nil
}
