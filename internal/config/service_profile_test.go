package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestDefaultIncludesHermesRuntimeServiceProfile(t *testing.T) {
	cfg := Default()
	profile, ok := cfg.Agents["hermes-runtime"]
	if !ok {
		t.Fatal("Default() missing hermes-runtime service agent profile")
	}
	if !profile.CanWrite {
		t.Fatal("hermes-runtime should be write-capable for service-vault operations")
	}
	if !profile.CanRunCommands {
		t.Fatal("hermes-runtime should be command-capable for runtime agent operations")
	}
	if profile.ApprovalMode != "none" {
		t.Fatalf("hermes-runtime ApprovalMode = %q, want none for noninteractive service mode", profile.ApprovalMode)
	}
}

func TestDefaultHermesRuntimeUsesExplicitServiceVaultPaths(t *testing.T) {
	cfg := Default()
	profile, ok := cfg.Agents["hermes-runtime"]
	if !ok {
		t.Fatal("Default() missing hermes-runtime service agent profile")
	}

	want := []string{
		"identities/gmail/hermes-agent",
		"identities/github/szponeczek",
		"identities/github/pazureczek",
		"providers/openrouter/hermes-runtime",
		"providers/elevenlabs/hermes-stt",
		"providers/search/local-dev",
		"tools/blogwatcher/rss-sync",
		"tools/discord/agent-gateway",
		"tools/airtable/project-tracker",
		"experiments/openpass-agent-vault",
		"synthetic/agent-vault",
		"synthetic/scanner",
	}
	if !reflect.DeepEqual(profile.AllowedPaths, want) {
		t.Fatalf("hermes-runtime AllowedPaths = %#v, want explicit service-vault paths %#v", profile.AllowedPaths, want)
	}
}

func TestDefaultHermesRuntimeRejectsWildcardAndHumanCredentialPathFamilies(t *testing.T) {
	cfg := Default()
	profile, ok := cfg.Agents["hermes-runtime"]
	if !ok {
		t.Fatal("Default() missing hermes-runtime service agent profile")
	}

	rejected := []string{
		"*",
		"personal/",
		"personal/agent",
		"root/",
		"root/admin",
		"admin/",
		"admin/openpass",
		"human/",
		"human/janusz",
		"janusz/",
		"janusz/openpass",
		"password-manager/",
		"browser/",
		"shell-history/",
		"imports/unknown/",
		"identities/gmail/janusz",
		"identities/github/janusz",
	}

	for _, path := range profile.AllowedPaths {
		for _, rejectedPrefix := range rejected {
			if path == rejectedPrefix || strings.HasPrefix(path, rejectedPrefix) {
				t.Fatalf("hermes-runtime AllowedPaths contains rejected path family %q via %q", rejectedPrefix, path)
			}
		}
	}
}
