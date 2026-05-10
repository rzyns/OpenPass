package credentialverify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func syntheticGitHubPAT() string {
	return "ghp_" + strings.Repeat("X", 36)
}

func TestFakeProviderReturnsTypedStatuses(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   Status
	}{
		{name: "valid", secret: "fake-valid-credential", want: StatusValid},
		{name: "invalid", secret: "fake-invalid-credential", want: StatusInvalid},
		{name: "permission denied", secret: "fake-permission-credential", want: StatusPermissionError},
		{name: "network error", secret: "fake-network-credential", want: StatusNetworkError},
		{name: "unknown", secret: "surprising", want: StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewRegistry().Verify(context.Background(), Request{Provider: "fake", Secret: tt.secret})
			if result.Status != tt.want {
				t.Fatalf("Status = %q, want %q", result.Status, tt.want)
			}
			if result.Provider != "fake" {
				t.Fatalf("Provider = %q, want fake", result.Provider)
			}
		})
	}
}

func TestGitHubProviderMapsHTTPStatusesWithoutLeakingSecret(t *testing.T) {
	secret := "" + syntheticGitHubPAT() + ""
	tests := []struct {
		name       string
		statusCode int
		want       Status
	}{
		{name: "valid", statusCode: http.StatusOK, want: StatusValid},
		{name: "invalid", statusCode: http.StatusUnauthorized, want: StatusInvalid},
		{name: "permission", statusCode: http.StatusForbidden, want: StatusPermissionError},
		{name: "unknown", statusCode: http.StatusTeapot, want: StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotAuth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(tt.statusCode)
			}))
			t.Cleanup(server.Close)

			registry := NewRegistry(WithGitHubBaseURL(server.URL))
			result := registry.Verify(context.Background(), Request{Provider: "github", Secret: secret})
			if result.Status != tt.want {
				t.Fatalf("Status = %q, want %q", result.Status, tt.want)
			}
			if gotAuth != "Bearer "+secret {
				t.Fatalf("GitHub provider did not send bearer auth header")
			}
			if result.ContainsSecret(secret) {
				t.Fatalf("verification result leaked secret: %+v", result)
			}
		})
	}
}

func TestGitHubProviderMapsTransportErrorWithoutLeakingSecret(t *testing.T) {
	secret := "" + syntheticGitHubPAT() + ""
	registry := NewRegistry(WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: synthetic failure")
	})}))

	result := registry.Verify(context.Background(), Request{Provider: "github", Secret: secret})
	if result.Status != StatusNetworkError {
		t.Fatalf("Status = %q, want %q", result.Status, StatusNetworkError)
	}
	if result.ContainsSecret(secret) {
		t.Fatalf("verification result leaked secret: %+v", result)
	}
}

func TestUnknownProviderReturnsUnknownWithoutLeakingSecret(t *testing.T) {
	secret := "secret-provider-value"
	result := NewRegistry().Verify(context.Background(), Request{Provider: "does-not-exist", Secret: secret})
	if result.Status != StatusUnknown {
		t.Fatalf("Status = %q, want %q", result.Status, StatusUnknown)
	}
	if !strings.Contains(result.Message, "unsupported provider") {
		t.Fatalf("Message = %q, want unsupported provider", result.Message)
	}
	if result.ContainsSecret(secret) {
		t.Fatalf("verification result leaked secret: %+v", result)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
