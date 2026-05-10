package masking

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// RedactionOptions controls how scanner output redacts detected secret spans.
type RedactionOptions struct {
	// Marker replaces each detected secret span. Defaults to "***".
	Marker string
}

// ScanOptions controls text scanning behavior.
type ScanOptions struct {
	Redaction RedactionOptions
}

// ScanReport is the safe, structured result of scanning a text payload.
type ScanReport struct {
	ScannedBytes int       `json:"scanned_bytes"`
	FindingCount int       `json:"finding_count"`
	Findings     []Finding `json:"findings"`
	RedactedText string    `json:"redacted_text"`
}

// Finding is a single detected secret finding. It intentionally omits the raw
// secret value in normal JSON output; Value is kept for internal tests/callers
// and should remain empty for public scanner results.
type Finding struct {
	DetectorName  string `json:"detector_name"`
	Severity      string `json:"severity"`
	Description   string `json:"description,omitempty"`
	LineNumber    int    `json:"line_number"`
	Start         int    `json:"start"`
	End           int    `json:"end"`
	Fingerprint   string `json:"fingerprint"`
	Value         string `json:"value,omitempty"`
	RedactedValue string `json:"redacted_value"`
}

type Scanner struct {
	registry *PatternRegistry
}

func NewScanner(registry *PatternRegistry) *Scanner {
	if registry == nil {
		registry = NewPatternRegistry()
	}
	return &Scanner{registry: registry}
}

func (s *Scanner) ScanText(text string, opts ScanOptions) ScanReport {
	marker := opts.Redaction.Marker
	if marker == "" {
		marker = "***"
	}

	matches := s.scanMatches(text)
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, Finding{
			DetectorName:  match.PatternName,
			Severity:      match.Severity,
			Description:   match.Description,
			LineNumber:    lineNumberForOffset(text, match.Start),
			Start:         match.Start,
			End:           match.End,
			Fingerprint:   fingerprint(match.PatternName, match.Value),
			RedactedValue: marker,
		})
	}

	return ScanReport{
		ScannedBytes: len(text),
		FindingCount: len(findings),
		Findings:     findings,
		RedactedText: redactMatches(text, matches, marker),
	}
}

func (s *Scanner) scanMatches(text string) []Match {
	patterns := s.registry.Patterns()
	var all []Match
	for _, p := range patterns {
		indexes := p.Regex.FindAllStringIndex(text, -1)
		for _, idx := range indexes {
			all = append(all, Match{
				PatternName: p.Name,
				Value:       text[idx[0]:idx[1]],
				Start:       idx[0],
				End:         idx[1],
				Severity:    p.Severity,
				Description: p.Description,
			})
		}
	}
	if len(all) == 0 {
		return nil
	}

	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Start != all[j].Start {
			return all[i].Start < all[j].Start
		}
		if severityRank(all[i].Severity) != severityRank(all[j].Severity) {
			return severityRank(all[i].Severity) > severityRank(all[j].Severity)
		}
		return (all[i].End - all[i].Start) > (all[j].End - all[j].Start)
	})

	selected := make([]Match, 0, len(all))
	for _, candidate := range all {
		replaced := false
		dropped := false
		for i := range selected {
			if !overlaps(candidate, selected[i]) {
				continue
			}
			if betterMatch(candidate, selected[i]) {
				selected[i] = candidate
				replaced = true
			} else {
				dropped = true
			}
			break
		}
		if !replaced && !dropped {
			selected = append(selected, candidate)
		}
	}

	sort.SliceStable(selected, func(i, j int) bool { return selected[i].Start < selected[j].Start })
	return selected
}

func overlaps(a, b Match) bool {
	return a.Start < b.End && b.Start < a.End
}

func betterMatch(candidate, current Match) bool {
	if severityRank(candidate.Severity) != severityRank(current.Severity) {
		return severityRank(candidate.Severity) > severityRank(current.Severity)
	}
	candidateLen := candidate.End - candidate.Start
	currentLen := current.End - current.Start
	if candidateLen != currentLen {
		return candidateLen > currentLen
	}
	return candidate.Start < current.Start
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func redactMatches(text string, matches []Match, marker string) string {
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, match := range matches {
		if match.Start < last {
			continue
		}
		b.WriteString(text[last:match.Start])
		b.WriteString(marker)
		last = match.End
	}
	b.WriteString(text[last:])
	return b.String()
}

func lineNumberForOffset(text string, offset int) int {
	if offset <= 0 {
		return 1
	}
	return strings.Count(text[:offset], "\n") + 1
}

func fingerprint(detectorName, value string) string {
	sum := sha256.Sum256([]byte(detectorName + "\x00" + value))
	return hex.EncodeToString(sum[:])[:16]
}
