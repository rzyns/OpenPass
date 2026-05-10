package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/danieljustus/OpenPass/internal/audit"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/vault"
)

type ServiceVaultCode string

const (
	CodeVaultUninitialized    ServiceVaultCode = "vault_uninitialized"
	CodeVaultLocked           ServiceVaultCode = "vault_locked"
	CodeMissingBootstrap      ServiceVaultCode = "missing_bootstrap"
	CodeUnlockProviderMissing ServiceVaultCode = "unlock_provider_missing"
	CodeUnlockProviderDenied  ServiceVaultCode = "unlock_provider_denied"
	CodeWrongPassphrase       ServiceVaultCode = "wrong_passphrase"
	CodeAgentProfileMissing   ServiceVaultCode = "agent_profile_missing"
	CodeInternalError         ServiceVaultCode = "internal_error"
)

type ServiceVaultError struct {
	Code    ServiceVaultCode          `json:"code"`
	Message string                    `json:"message"`
	Context *ServiceVaultErrorContext `json:"context,omitempty"`
}

type ServiceVaultErrorContext struct {
	Agent     string   `json:"agent,omitempty"`
	Provider  string   `json:"provider,omitempty"`
	Providers []string `json:"providers,omitempty"`
}

func NewServiceVaultError(code ServiceVaultCode, message string, context *ServiceVaultErrorContext) *ServiceVaultError {
	return &ServiceVaultError{Code: code, Message: message, Context: sanitizeServiceVaultErrorContext(context)}
}

func (e *ServiceVaultError) Error() string {
	if e == nil {
		return "service vault error"
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return string(e.Code)
	}
	return string(payload)
}

func (e *ServiceVaultError) ToolResult() *CallToolResult {
	return NewToolResultError(e.Error())
}

type ServiceUnlocker func(context.Context) (*vault.Vault, error)

func NewEnvironmentServiceUnlocker(vaultDir string) ServiceUnlocker {
	return func(ctx context.Context) (*vault.Vault, error) {
		_ = ctx
		passphrase, provider, ok := consumeServicePassphraseEnv()
		if !ok {
			return nil, NewServiceVaultError(CodeMissingBootstrap, "service vault unlock material is unavailable", &ServiceVaultErrorContext{
				Providers: []string{"service_env", "legacy_env"},
			})
		}
		defer crypto.Wipe(passphrase)

		v, err := vault.OpenWithPassphrase(vaultDir, passphrase)
		if err != nil {
			return nil, NewServiceVaultError(codeForUnlockError(err), "service vault unlock failed", &ServiceVaultErrorContext{
				Provider: provider,
			})
		}
		return v, nil
	}
}

func consumeServicePassphraseEnv() ([]byte, string, bool) {
	for _, provider := range []struct {
		EnvName string
		Label   string
	}{
		{EnvName: "OPENPASS_SERVICE_VAULT_PASSPHRASE", Label: "service_env"},
		{EnvName: "OPENPASS_PASSPHRASE", Label: "legacy_env"},
	} {
		name := provider.EnvName
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			continue
		}
		_ = os.Unsetenv(name)
		return []byte(value), provider.Label, true
	}
	return nil, "", false
}

func codeForUnlockError(err error) ServiceVaultCode {
	if err == nil {
		return CodeInternalError
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no such file") || strings.Contains(msg, "not initialized"):
		return CodeVaultUninitialized
	case strings.Contains(msg, "incorrect") || strings.Contains(msg, "decrypt") || strings.Contains(msg, "identity"):
		return CodeWrongPassphrase
	default:
		return CodeVaultLocked
	}
}

func NewServiceRuntimeServer(vaultDir, agentName, transport string, unlocker ServiceUnlocker) (*Server, error) {
	cfg, err := config.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		return nil, NewServiceVaultError(CodeVaultUninitialized, "service vault config unavailable", nil)
	}
	if agentName == "" {
		agentName = cfg.DefaultAgent
	}
	agent, ok := cfg.Agents[agentName]
	if !ok {
		return nil, NewServiceVaultError(CodeAgentProfileMissing, "agent profile is not configured", &ServiceVaultErrorContext{Agent: agentName})
	}
	agent.Name = agentName

	auditLog, err := audit.New(agentName, vaultDir)
	if err != nil {
		return nil, err
	}
	if unlocker == nil {
		unlocker = NewEnvironmentServiceUnlocker(vaultDir)
	}
	return &Server{
		vaultDir:        vaultDir,
		serviceConfig:   cfg,
		serviceUnlocker: unlocker,
		agent:           &agent,
		auditLog:        auditLog,
		transport:       transport,
	}, nil
}

func (s *Server) ensureUnlocked(ctx context.Context) *ServiceVaultError {
	if s == nil {
		return NewServiceVaultError(CodeInternalError, "MCP server is unavailable", nil)
	}
	s.serviceMu.Lock()
	defer s.serviceMu.Unlock()
	if s.vault != nil {
		return nil
	}
	if s.serviceUnlocker == nil {
		return NewServiceVaultError(CodeVaultLocked, "service vault is locked", nil)
	}
	v, err := s.serviceUnlocker(ctx)
	if err != nil {
		var svcErr *ServiceVaultError
		if errors.As(err, &svcErr) {
			return svcErr
		}
		return NewServiceVaultError(codeForUnlockError(err), "service vault unlock failed", nil)
	}
	if v == nil {
		return NewServiceVaultError(CodeVaultLocked, "service vault is locked", nil)
	}
	s.vault = v
	if s.serviceConfig == nil && v.Config != nil {
		s.serviceConfig = v.Config
	}
	return nil
}

func toolRequiresUnlockedVault(name string) bool {
	switch name {
	case "health", "get_auth_status", "generate_password", "sanitize_output", "scan_text":
		return false
	default:
		return true
	}
}

func sanitizeServiceVaultErrorContext(context *ServiceVaultErrorContext) *ServiceVaultErrorContext {
	if context == nil {
		return nil
	}
	clean := &ServiceVaultErrorContext{}
	if isSafeServiceContextValue(context.Agent) {
		clean.Agent = context.Agent
	}
	if isSafeServiceContextValue(context.Provider) {
		clean.Provider = context.Provider
	}
	for _, provider := range context.Providers {
		if isSafeServiceContextValue(provider) {
			clean.Providers = append(clean.Providers, provider)
		}
	}
	if clean.Agent == "" && clean.Provider == "" && len(clean.Providers) == 0 {
		return nil
	}
	return clean
}

func isSafeServiceContextValue(value string) bool {
	lower := strings.ToLower(value)
	return value != "" && !strings.Contains(lower, "passphrase") && !strings.Contains(lower, "password") && !strings.Contains(lower, "token") && !strings.Contains(lower, "secret")
}
