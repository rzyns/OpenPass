package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/danieljustus/OpenPass/internal/metrics"
	"github.com/danieljustus/OpenPass/internal/vault"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

type listEntrySummary struct {
	Path             string `json:"path"`
	Type             string `json:"type,omitempty"`
	UsageHint        string `json:"usage_hint,omitempty"`
	AutoRotate       bool   `json:"auto_rotate,omitempty"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	ReviewAfter      string `json:"review_after,omitempty"`
	LastRotatedAt    string `json:"last_rotated_at,omitempty"`
	RotationInterval string `json:"rotation_interval,omitempty"`
	Expiring         bool   `json:"expiring,omitempty"`
	RotationStale    bool   `json:"rotation_stale,omitempty"`
	MetadataError    string `json:"metadata_error,omitempty"`
	HasValue         bool   `json:"has_value,omitempty"`
	FieldCount       int    `json:"field_count,omitempty"`
	sortAt           time.Time
}

func (s *Server) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now().UTC()
}

func (s *Server) handleList(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	prefix, err := req.RequireString("prefix")
	if err != nil {
		prefix = ""
	}

	if !s.checkScope(prefix) {
		s.logAudit(ctx, "list", prefix, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", prefix)
	}

	svc := vaultsvc.New(slog.Default(), s.vault)
	_, span := metrics.StartSpan(ctx, "vault.List")
	paths, err := svc.List(prefix)
	span.End()
	if err != nil {
		s.logAudit(ctx, "list", prefix, false)
		metrics.RecordVaultOperation("list", "error")
		return vaultServiceErrorResult(err)
	}

	s.logAudit(ctx, "list", prefix, true)
	metrics.RecordVaultOperation("list", "success")

	includeDetails := req.GetBool("include_details", true)

	if !includeDetails {
		result, marshalErr := json.Marshal(paths)
		if marshalErr != nil {
			return nil, marshalErr
		}
		return NewToolResultText(string(result)), nil
	}

	now := s.currentTime()
	expiringWithinRaw := req.GetString("expiring_within", "")
	staleAfterRaw := req.GetString("stale_after", "")
	var expiringWithin time.Duration
	var staleAfter time.Duration
	if expiringWithinRaw != "" {
		var parseErr error
		expiringWithin, parseErr = vault.ParseLifecycleDuration(expiringWithinRaw)
		if parseErr != nil {
			return NewToolResultError(fmt.Sprintf("invalid expiring_within: %v", parseErr)), nil
		}
	}
	if staleAfterRaw != "" {
		var parseErr error
		staleAfter, parseErr = vault.ParseLifecycleDuration(staleAfterRaw)
		if parseErr != nil {
			return NewToolResultError(fmt.Sprintf("invalid stale_after: %v", parseErr)), nil
		}
	}
	filterLifecycle := expiringWithinRaw != "" || staleAfterRaw != ""

	summaries := make([]listEntrySummary, 0, len(paths))
	for _, path := range paths {
		entry, getErr := svc.GetEntry(path)
		if getErr != nil {
			continue
		}

		summary := buildListEntrySummary(path, entry, now, expiringWithin, staleAfter)
		if filterLifecycle && !summary.Expiring && !summary.RotationStale && summary.MetadataError == "" {
			continue
		}
		summaries = append(summaries, summary)
	}

	sort.SliceStable(summaries, func(i, j int) bool {
		left, right := summaries[i], summaries[j]
		if left.sortAt.IsZero() != right.sortAt.IsZero() {
			return !left.sortAt.IsZero()
		}
		if !left.sortAt.Equal(right.sortAt) {
			return left.sortAt.Before(right.sortAt)
		}
		return left.Path < right.Path
	})

	result, err := json.Marshal(summaries)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(result)), nil
}

func buildListEntrySummary(path string, entry *vault.Entry, now time.Time, expiringWithin, staleAfter time.Duration) listEntrySummary {
	summary := listEntrySummary{
		Path:       path,
		Type:       string(entry.SecretMetadata.Type),
		UsageHint:  entry.SecretMetadata.UsageHint,
		AutoRotate: entry.SecretMetadata.AutoRotate,
		HasValue:   len(entry.Data) > 0,
		FieldCount: len(entry.Data),
	}
	meta := entry.SecretMetadata
	if meta.ExpiresAt != nil {
		summary.ExpiresAt = meta.ExpiresAt.Format(time.RFC3339)
		if expiringWithin > 0 && !meta.ExpiresAt.After(now.Add(expiringWithin)) {
			summary.Expiring = true
			summary.sortAt = earlierNonZero(summary.sortAt, *meta.ExpiresAt)
		}
	}
	if meta.ReviewAfter != nil {
		summary.ReviewAfter = meta.ReviewAfter.Format(time.RFC3339)
		if staleAfter > 0 && !meta.ReviewAfter.After(now) {
			summary.RotationStale = true
			summary.sortAt = earlierNonZero(summary.sortAt, *meta.ReviewAfter)
		}
	}
	if meta.LastRotatedAt != nil {
		summary.LastRotatedAt = meta.LastRotatedAt.Format(time.RFC3339)
	}
	if meta.RotationInterval != "" {
		summary.RotationInterval = meta.RotationInterval
		interval, err := vault.ParseLifecycleDuration(meta.RotationInterval)
		if err != nil {
			summary.MetadataError = fmt.Sprintf("invalid rotation_interval: %v", err)
		} else if meta.LastRotatedAt != nil {
			due := meta.LastRotatedAt.Add(interval)
			if !due.After(now) || (staleAfter > 0 && !due.After(now.Add(staleAfter))) {
				summary.RotationStale = true
				summary.sortAt = earlierNonZero(summary.sortAt, due)
			}
		}
	}
	return summary
}

func earlierNonZero(current, candidate time.Time) time.Time {
	if current.IsZero() || candidate.Before(current) {
		return candidate
	}
	return current
}
