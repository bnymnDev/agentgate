package taint

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractFindsSecrets(t *testing.T) {
	env := `# production
DATABASE_URL=postgres://app:s3cr3t-Pa55w0rd@db.internal:5432/app
STRIPE_SECRET_KEY=sk_live_51HxYzAbCdEf0123456789
OPENAI_API_KEY="sk-proj-AbC123dEf456GhI789jKl012"
LOG_LEVEL=debug
APP_NAME=billing-service
PASSWORD = correct horse
SESSION_SECRET: 9f2c1e8b7a6d5c4b3a2f1e0d
`
	got := Extract(env, 0)
	for _, want := range []string{
		"sk_live_51HxYzAbCdEf0123456789",
		"sk-proj-AbC123dEf456GhI789jKl012",
		"s3cr3t-Pa55w0rd",
		"9f2c1e8b7a6d5c4b3a2f1e0d",
	} {
		require.Contains(t, got, want)
	}
	for _, not := range []string{"debug", "billing-service", "correct"} {
		require.NotContains(t, got, not)
	}
}

func TestExtractLeavesOrdinaryTextAlone(t *testing.T) {
	text := `The quick brown fox jumps over the lazy dog. See /usr/local/share/applications/firefox.desktop
and https://github.com/bnymnDev/agentgate/blob/main/README.md for details. Version 2026.11.04-beta.
API_KEY=REDACTED and TOKEN=${GITHUB_TOKEN} and secret=your_secret_here`
	require.Empty(t, Extract(text, 0))
}

func TestMinLength(t *testing.T) {
	require.Empty(t, Extract("API_KEY=abc123xyz", 0))
	require.Equal(t, []string{"abc123xyz"}, Extract("API_KEY=abc123xyz", 6))
}
