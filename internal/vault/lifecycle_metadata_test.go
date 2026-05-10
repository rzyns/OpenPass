package vault

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSecretMetadataLifecycleJSONParsesOptionalFields(t *testing.T) {
	raw := []byte(`{
		"type":"api_key",
		"expires_at":"2026-06-01T00:00:00Z",
		"review_after":"2026-05-15T00:00:00Z",
		"last_rotated_at":"2026-04-01T00:00:00Z",
		"rotation_interval":"30d"
	}`)

	var meta SecretMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("unmarshal lifecycle metadata: %v", err)
	}

	if meta.ExpiresAt == nil || meta.ExpiresAt.Format(time.RFC3339) != "2026-06-01T00:00:00Z" {
		t.Fatalf("ExpiresAt = %v, want 2026-06-01T00:00:00Z", meta.ExpiresAt)
	}
	if meta.ReviewAfter == nil || meta.ReviewAfter.Format(time.RFC3339) != "2026-05-15T00:00:00Z" {
		t.Fatalf("ReviewAfter = %v, want 2026-05-15T00:00:00Z", meta.ReviewAfter)
	}
	if meta.LastRotatedAt == nil || meta.LastRotatedAt.Format(time.RFC3339) != "2026-04-01T00:00:00Z" {
		t.Fatalf("LastRotatedAt = %v, want 2026-04-01T00:00:00Z", meta.LastRotatedAt)
	}
	if meta.RotationInterval != "30d" {
		t.Fatalf("RotationInterval = %q, want 30d", meta.RotationInterval)
	}
}

func TestSecretMetadataLifecycleJSONRejectsInvalidTimestamp(t *testing.T) {
	var meta SecretMetadata
	err := json.Unmarshal([]byte(`{"review_after":"not-a-time"}`), &meta)
	if err == nil {
		t.Fatal("unmarshal invalid review_after succeeded, want error")
	}
	if !strings.Contains(err.Error(), "review_after") {
		t.Fatalf("error = %v, want field name review_after", err)
	}
}

func TestSecretMetadataLifecycleAbsentFieldsAreZero(t *testing.T) {
	var meta SecretMetadata
	if err := json.Unmarshal([]byte(`{"type":"password"}`), &meta); err != nil {
		t.Fatalf("unmarshal absent lifecycle fields: %v", err)
	}
	if meta.ExpiresAt != nil || meta.ReviewAfter != nil || meta.LastRotatedAt != nil || meta.RotationInterval != "" {
		t.Fatalf("absent lifecycle fields should stay zero: %+v", meta)
	}
}

func TestParseLifecycleDurationAcceptsDaysAndRejectsInvalid(t *testing.T) {
	got, err := ParseLifecycleDuration("45d")
	if err != nil {
		t.Fatalf("ParseLifecycleDuration(45d) error = %v", err)
	}
	if got != 45*24*time.Hour {
		t.Fatalf("ParseLifecycleDuration(45d) = %v, want 1080h", got)
	}

	if _, err := ParseLifecycleDuration("soon"); err == nil {
		t.Fatal("ParseLifecycleDuration(soon) succeeded, want error")
	}
}
