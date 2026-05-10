package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildScanTextJSONRedactsStructuredFindings(t *testing.T) {
	secret := "ghp_" + strings.Repeat("C", 36)
	payload, err := buildScanTextJSON("token="+secret, scanTextOptions{})
	if err != nil {
		t.Fatalf("buildScanTextJSON() error = %v", err)
	}
	if strings.Contains(string(payload), secret) {
		t.Fatalf("scan-text JSON leaked raw secret: %s", payload)
	}

	var report struct {
		FindingCount int `json:"finding_count"`
		Findings     []struct {
			DetectorName  string `json:"detector_name"`
			Severity      string `json:"severity"`
			Value         string `json:"value,omitempty"`
			RedactedValue string `json:"redacted_value"`
		} `json:"findings"`
		RedactedText string `json:"redacted_text"`
	}
	if err := json.Unmarshal(payload, &report); err != nil {
		t.Fatalf("scan-text JSON did not unmarshal: %v", err)
	}
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("got %d findings (%d stored), want 1", report.FindingCount, len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.DetectorName != "github_pat" || finding.Severity != "high" {
		t.Fatalf("unexpected finding metadata: %#v", finding)
	}
	if finding.Value != "" {
		t.Fatalf("finding raw Value should be omitted/empty, got %q", finding.Value)
	}
	if finding.RedactedValue == "" || !strings.Contains(report.RedactedText, finding.RedactedValue) {
		t.Fatalf("missing coherent redaction in report: %#v", report)
	}
}

func TestBuildScanTextJSONHonorsCustomMarker(t *testing.T) {
	secret := "sk_test_" + strings.Repeat("D", 24)
	payload, err := buildScanTextJSON("stripe="+secret, scanTextOptions{marker: "[SAFE]"})
	if err != nil {
		t.Fatalf("buildScanTextJSON() error = %v", err)
	}
	if strings.Contains(string(payload), secret) {
		t.Fatal("scan-text JSON leaked raw secret")
	}
	if !strings.Contains(string(payload), `"redacted_text":"stripe=[SAFE]"`) {
		t.Fatalf("custom marker not reflected in payload: %s", payload)
	}
}
