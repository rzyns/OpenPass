package vault

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func parseOptionalRFC3339Field(field string, raw *string) (*time.Time, error) {
	if raw == nil || *raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, *raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}
	return &parsed, nil
}

// ParseLifecycleDuration parses lifecycle durations used by metadata filters.
// It accepts normal Go durations (for example "720h") and day shorthand
// (for example "30d") used by agent-vault rotation policy metadata.
func ParseLifecycleDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty lifecycle duration")
	}
	if strings.HasSuffix(raw, "d") {
		daysRaw := strings.TrimSuffix(raw, "d")
		days, err := strconv.ParseFloat(daysRaw, 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day duration %q", raw)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return d, nil
}
