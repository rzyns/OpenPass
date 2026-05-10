package credentialverify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Status is the typed result of a non-mutating credential verification check.
type Status string

const (
	StatusValid           Status = "valid"
	StatusInvalid         Status = "invalid"
	StatusNetworkError    Status = "network_error"
	StatusPermissionError Status = "permission_error"
	StatusUnknown         Status = "unknown"
)

// Request describes a credential verification attempt. Secret must never be
// copied into Result fields, logs, or errors.
type Request struct {
	Provider string
	Secret   string
}

// Result is safe to return to agents and logs: it intentionally omits the
// credential value and includes only typed status plus non-secret context.
type Result struct {
	Provider  string    `json:"provider"`
	Status    Status    `json:"status"`
	CheckedAt time.Time `json:"checked_at"`
	Message   string    `json:"message,omitempty"`
}

// ContainsSecret is primarily a test helper that verifies Result remains safe
// to serialize or display.
func (r Result) ContainsSecret(secret string) bool {
	if secret == "" {
		return false
	}
	return strings.Contains(r.Provider, secret) || strings.Contains(string(r.Status), secret) || strings.Contains(r.Message, secret)
}

type provider interface {
	Verify(context.Context, string) Result
}

// Registry owns provider selection and shared verifier dependencies.
type Registry struct {
	providers map[string]provider
}

type registryConfig struct {
	httpClient    *http.Client
	githubBaseURL string
}

// Option customizes verifier dependencies. Tests use options to supply fakes
// and local HTTP servers; production uses safe defaults.
type Option func(*registryConfig)

func WithHTTPClient(client *http.Client) Option {
	return func(cfg *registryConfig) {
		if client != nil {
			cfg.httpClient = client
		}
	}
}

func WithGitHubBaseURL(baseURL string) Option {
	return func(cfg *registryConfig) {
		if strings.TrimSpace(baseURL) != "" {
			cfg.githubBaseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

func NewRegistry(options ...Option) *Registry {
	cfg := registryConfig{
		httpClient:    http.DefaultClient,
		githubBaseURL: "https://api.github.com",
	}
	for _, option := range options {
		option(&cfg)
	}
	return &Registry{providers: map[string]provider{
		"fake":   fakeProvider{},
		"github": githubProvider{client: cfg.httpClient, baseURL: cfg.githubBaseURL},
	}}
}

func (r *Registry) Verify(ctx context.Context, req Request) Result {
	providerName := strings.ToLower(strings.TrimSpace(req.Provider))
	if providerName == "" {
		providerName = "fake"
	}
	if r == nil {
		r = NewRegistry()
	}
	verifier, ok := r.providers[providerName]
	if !ok {
		return result(providerName, StatusUnknown, "unsupported provider")
	}
	if strings.TrimSpace(req.Secret) == "" {
		return result(providerName, StatusUnknown, "credential value is empty")
	}
	out := verifier.Verify(ctx, req.Secret)
	out.Provider = providerName
	if out.CheckedAt.IsZero() {
		out.CheckedAt = time.Now().UTC()
	}
	return out
}

func result(providerName string, status Status, message string) Result {
	return Result{Provider: providerName, Status: status, CheckedAt: time.Now().UTC(), Message: message}
}

type fakeProvider struct{}

func (fakeProvider) Verify(_ context.Context, secret string) Result {
	switch strings.ToLower(strings.TrimSpace(secret)) {
	case "valid", "fake-valid-credential":
		return result("fake", StatusValid, "fake verifier accepted credential")
	case "invalid", "fake-invalid-credential":
		return result("fake", StatusInvalid, "fake verifier rejected credential")
	case "permission", "fake-permission-credential":
		return result("fake", StatusPermissionError, "fake verifier reported insufficient permission")
	case "network", "fake-network-credential":
		return result("fake", StatusNetworkError, "fake verifier reported network failure")
	default:
		return result("fake", StatusUnknown, "fake verifier could not classify credential")
	}
}

type githubProvider struct {
	client  *http.Client
	baseURL string
}

func (p githubProvider) Verify(ctx context.Context, secret string) Result {
	client := p.client
	if client == nil {
		client = http.DefaultClient
	}
	baseURL := strings.TrimRight(p.baseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/user", nil)
	if err != nil {
		return result("github", StatusUnknown, "could not build verification request")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return result("github", StatusNetworkError, "verification request did not complete")
		}
		return result("github", StatusNetworkError, "verification request failed")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return result("github", StatusValid, "GitHub token is accepted")
	case http.StatusUnauthorized:
		return result("github", StatusInvalid, "GitHub token is rejected")
	case http.StatusForbidden:
		return result("github", StatusPermissionError, "GitHub token lacks permission or is rate limited")
	default:
		return result("github", StatusUnknown, fmt.Sprintf("GitHub verifier returned HTTP %d", resp.StatusCode))
	}
}
