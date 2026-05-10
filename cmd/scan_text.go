package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/masking"
)

type scanTextOptions struct {
	marker string
}

var scanTextMarker string

var scanTextCmd = &cobra.Command{
	Use:   "scan-text [text]",
	Short: "Scan text for possible secrets and return safe structured findings",
	Long:  "Scan text for possible secrets and return JSON findings plus redacted text. Raw detected values are not returned.",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		text, err := scanTextInput(args, cmd.InOrStdin())
		if err != nil {
			return err
		}
		payload, err := buildScanTextJSON(text, scanTextOptions{marker: scanTextMarker})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(payload))
		return err
	},
}

func init() {
	scanTextCmd.Flags().StringVar(&scanTextMarker, "marker", "", "custom redaction marker (default: ***)")
	rootCmd.AddCommand(scanTextCmd)
}

func scanTextInput(args []string, stdin io.Reader) (string, error) {
	if len(args) > 0 {
		return strings.Join(args, " "), nil
	}
	if stdin == nil {
		stdin = os.Stdin
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return string(data), nil
}

func buildScanTextJSON(text string, opts scanTextOptions) ([]byte, error) {
	report := masking.NewScanner(masking.NewPatternRegistry()).ScanText(text, masking.ScanOptions{
		Redaction: masking.RedactionOptions{Marker: opts.marker},
	})
	payload, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal scan-text report: %w", err)
	}
	return payload, nil
}
