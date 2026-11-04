package flow

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const issue = `Customer ACME Corp reported that invoices from March are missing the
VAT line. Their contact is Jane Roe, jane.roe@acme.example, and the contract
number is CN-2026-0042. Please do not share this outside the support team.`

func TestSharedPassageIsFound(t *testing.T) {
	s := NewSet(10000)
	require.Positive(t, s.Add(issue))

	copied := "Summary for #general: Their contact is Jane Roe, jane.roe@acme.example, and the contract number is CN-2026-0042."
	require.True(t, s.Shares(copied))

	rewrapped := strings.ToUpper("their   contact is jane roe,\n\tjane.roe@acme.example")
	require.True(t, s.Shares(rewrapped), "case and whitespace do not hide a copy")

	short := "contract number"
	require.False(t, s.Shares(short), "a few common words are not a copy")
	require.False(t, s.Shares("The build is green and the release is on Thursday."))
}

// Every passage of Guaranteed characters is found, wherever it sits.
func TestGuarantee(t *testing.T) {
	text := strings.Repeat("abcdefghij0123456789klmnopqrst", 20) + issue
	s := NewSet(100000)
	s.Add(text)
	norm := string(normalize(text))
	for i := 0; i+Guaranteed <= len(norm); i += 7 {
		require.True(t, s.Shares("xx "+norm[i:i+Guaranteed]+" yy"), "passage at %d", i)
	}
}

func TestBounded(t *testing.T) {
	s := NewSet(10)
	s.Add(issue)
	require.Equal(t, 10, s.Len())
}
