package masking

import (
	"regexp"
	"strings"
	"testing"
)

func TestScanTextReturnsStructuredRedactedFindings(t *testing.T) {
	secret := "ghp_" + strings.Repeat("A", 36)
	input := "before\nGITHUB_TOKEN=" + secret + "\nafter"

	report := NewScanner(NewPatternRegistry()).ScanText(input, ScanOptions{})

	if report.ScannedBytes != len(input) {
		t.Fatalf("ScannedBytes = %d, want %d", report.ScannedBytes, len(input))
	}
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("got %d findings (%d stored), want 1", report.FindingCount, len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.DetectorName != "github_pat" {
		t.Fatalf("DetectorName = %q, want github_pat", finding.DetectorName)
	}
	if finding.Severity != "high" || finding.Description == "" {
		t.Fatalf("expected detector severity/description metadata, got severity=%q description=%q", finding.Severity, finding.Description)
	}
	if finding.LineNumber != 2 {
		t.Fatalf("LineNumber = %d, want 2", finding.LineNumber)
	}
	if finding.Value != "" {
		t.Fatalf("finding leaked raw value %q", finding.Value)
	}
	if finding.RedactedValue == "" || strings.Contains(finding.RedactedValue, secret) {
		t.Fatalf("RedactedValue = %q, must be non-empty and must not contain raw secret", finding.RedactedValue)
	}
	if finding.Fingerprint == "" {
		t.Fatal("expected stable non-empty fingerprint")
	}
	if !strings.Contains(report.RedactedText, finding.RedactedValue) {
		t.Fatalf("RedactedText %q does not contain finding redaction %q", report.RedactedText, finding.RedactedValue)
	}
	if strings.Contains(report.RedactedText, secret) {
		t.Fatalf("RedactedText leaked raw secret")
	}
}

func TestScanTextSupportsCustomRedactionMarker(t *testing.T) {
	secret := "sk_live_" + strings.Repeat("B", 24)
	input := "stripe=" + secret

	report := NewScanner(NewPatternRegistry()).ScanText(input, ScanOptions{Redaction: RedactionOptions{Marker: "[REDACTED-SENSITIVE-VALUE]"}})

	if report.FindingCount != 1 {
		t.Fatalf("FindingCount = %d, want 1", report.FindingCount)
	}
	if report.RedactedText != "stripe=[REDACTED-SENSITIVE-VALUE]" {
		t.Fatalf("RedactedText = %q", report.RedactedText)
	}
	if got := report.Findings[0].RedactedValue; got != "[REDACTED-SENSITIVE-VALUE]" {
		t.Fatalf("RedactedValue = %q, want custom marker", got)
	}
}

func TestScanTextDoesNotFlagUUIDFalsePositive(t *testing.T) {
	input := "request id 123e4567-e89b-12d3-a456-426614174000 is not a secret"

	report := NewScanner(NewPatternRegistry()).ScanText(input, ScanOptions{})

	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("expected no findings for UUID-like text, got %#v", report.Findings)
	}
	if report.RedactedText != input {
		t.Fatalf("RedactedText changed unexpectedly: %q", report.RedactedText)
	}
}

func TestScanTextOverlapKeepsHighestSeverityDetector(t *testing.T) {
	registry := &PatternRegistry{}
	registry.AddPattern(SecretPattern{
		Name:        "wide_low",
		Regex:       regexp.MustCompile(`TOKEN-[A-Z0-9]+`),
		Description: "wide token",
		Severity:    "low",
	})
	registry.AddPattern(SecretPattern{
		Name:        "exact_high",
		Regex:       regexp.MustCompile(`TOKEN-ABCDEF123456`),
		Description: "exact token",
		Severity:    "high",
	})

	report := NewScanner(registry).ScanText("value TOKEN-ABCDEF123456", ScanOptions{})

	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("got findings %#v, want exactly one overlap-collapsed finding", report.Findings)
	}
	if got := report.Findings[0].DetectorName; got != "exact_high" {
		t.Fatalf("DetectorName = %q, want exact_high", got)
	}
	if strings.Contains(report.RedactedText, "TOKEN-ABCDEF123456") {
		t.Fatalf("RedactedText leaked overlapped token")
	}
}
