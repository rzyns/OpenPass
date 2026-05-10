package cmd

import (
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"

	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

type listEntryOutput struct {
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
	sortAt           time.Time
}

var (
	listExpiringWithin string
	listStaleAfter     string
)

var listCmd = &cobra.Command{
	Use:     "list [prefix]",
	Aliases: []string{"ls"},
	Short:   "List password entries",
	Example: `  # List all entries
  openpass list

  # List entries under "work/" prefix
  openpass list work/

  # JSON output
  openpass list --output json`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withVault(func(svc vaultsvc.Service) error {
			maybeAutoPull(svc.GetDir(), svc.Vault().Config)
			prefix := ""
			if len(args) > 0 {
				prefix = args[0]
			}

			entries, err := svc.List(prefix)
			if err != nil {
				return fmt.Errorf("cannot list entries: %w", err)
			}
			expiringWithin, staleAfter, err := parseListLifecycleFilters()
			if err != nil {
				return err
			}
			filterLifecycle := listExpiringWithin != "" || listStaleAfter != ""
			now := time.Now().UTC()

			if outputFormat != "text" {
				outputs := make([]listEntryOutput, 0, len(entries))
				for _, path := range entries {
					output := listEntryOutput{Path: path}
					entry, err := vaultpkg.ReadEntry(svc.GetDir(), path, svc.GetIdentity())
					if err == nil {
						output = buildListEntryOutput(path, entry, now, expiringWithin, staleAfter)
					}
					if filterLifecycle && !output.Expiring && !output.RotationStale && output.MetadataError == "" {
						continue
					}
					outputs = append(outputs, output)
				}
				sort.SliceStable(outputs, func(i, j int) bool {
					left, right := outputs[i], outputs[j]
					if left.sortAt.IsZero() != right.sortAt.IsZero() {
						return !left.sortAt.IsZero()
					}
					if !left.sortAt.Equal(right.sortAt) {
						return left.sortAt.Before(right.sortAt)
					}
					return left.Path < right.Path
				})
				if err := PrintResult(outputs); err != nil {
					return err
				}
				return nil
			}

			for _, e := range entries {
				if filterLifecycle {
					entry, readErr := vaultpkg.ReadEntry(svc.GetDir(), e, svc.GetIdentity())
					if readErr != nil {
						continue
					}
					output := buildListEntryOutput(e, entry, now, expiringWithin, staleAfter)
					if !output.Expiring && !output.RotationStale && output.MetadataError == "" {
						continue
					}
				}
				printlnQuietAware(e)
			}

			return nil
		})
	},
}

func init() {
	listCmd.Flags().StringVar(&listExpiringWithin, "expiring-within", "", "Only include credentials expiring within this duration (for example 72h or 30d)")
	listCmd.Flags().StringVar(&listStaleAfter, "stale-after", "", "Only include credentials stale for rotation/review within this duration (for example 7d)")
	rootCmd.AddCommand(listCmd)
}

func parseListLifecycleFilters() (time.Duration, time.Duration, error) {
	var expiringWithin time.Duration
	var staleAfter time.Duration
	if listExpiringWithin != "" {
		parsed, err := vaultpkg.ParseLifecycleDuration(listExpiringWithin)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid --expiring-within: %w", err)
		}
		expiringWithin = parsed
	}
	if listStaleAfter != "" {
		parsed, err := vaultpkg.ParseLifecycleDuration(listStaleAfter)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid --stale-after: %w", err)
		}
		staleAfter = parsed
	}
	return expiringWithin, staleAfter, nil
}

func buildListEntryOutput(path string, entry *vaultpkg.Entry, now time.Time, expiringWithin, staleAfter time.Duration) listEntryOutput {
	output := listEntryOutput{
		Path:       path,
		Type:       string(entry.SecretMetadata.Type),
		UsageHint:  entry.SecretMetadata.UsageHint,
		AutoRotate: entry.SecretMetadata.AutoRotate,
	}
	meta := entry.SecretMetadata
	if meta.ExpiresAt != nil {
		output.ExpiresAt = meta.ExpiresAt.Format(time.RFC3339)
		if expiringWithin > 0 && !meta.ExpiresAt.After(now.Add(expiringWithin)) {
			output.Expiring = true
			output.sortAt = earlierListOutputTime(output.sortAt, *meta.ExpiresAt)
		}
	}
	if meta.ReviewAfter != nil {
		output.ReviewAfter = meta.ReviewAfter.Format(time.RFC3339)
		if staleAfter > 0 && !meta.ReviewAfter.After(now) {
			output.RotationStale = true
			output.sortAt = earlierListOutputTime(output.sortAt, *meta.ReviewAfter)
		}
	}
	if meta.LastRotatedAt != nil {
		output.LastRotatedAt = meta.LastRotatedAt.Format(time.RFC3339)
	}
	if meta.RotationInterval != "" {
		output.RotationInterval = meta.RotationInterval
		interval, err := vaultpkg.ParseLifecycleDuration(meta.RotationInterval)
		if err != nil {
			output.MetadataError = fmt.Sprintf("invalid rotation_interval: %v", err)
		} else if meta.LastRotatedAt != nil {
			due := meta.LastRotatedAt.Add(interval)
			if !due.After(now) || (staleAfter > 0 && !due.After(now.Add(staleAfter))) {
				output.RotationStale = true
				output.sortAt = earlierListOutputTime(output.sortAt, due)
			}
		}
	}
	return output
}

func earlierListOutputTime(current, candidate time.Time) time.Time {
	if current.IsZero() || candidate.Before(current) {
		return candidate
	}
	return current
}
