package canary

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerateLooksLikeTheRealThing(t *testing.T) {
	for kind, prefix := range map[string]string{"aws": "AKIA", "github": "ghp_", "openai": "sk-proj-", "stripe": "sk_live_"} {
		c, err := Generate(kind, "")
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(c.Values[0], prefix), "%s: %s", kind, c.Values[0])
		require.NotEmpty(t, c.Decoy())
		for _, v := range c.Values {
			require.Contains(t, c.Decoy(), v)
			require.Contains(t, c.DecoyFor("/srv/app/.env.production"), v)
		}
	}
	a, _ := Generate("aws", "")
	b, _ := Generate("aws", "")
	// A decoy looks like what is usually in a file of that name.
	require.True(t, strings.HasPrefix(a.DecoyFor("/srv/app/.env.production"), "AWS_ACCESS_KEY_ID="+a.Values[0]+"\n"))
	require.True(t, strings.HasPrefix(a.DecoyFor("/srv/app/prod.env"), "AWS_ACCESS_KEY_ID="))
	require.True(t, strings.HasPrefix(a.DecoyFor("/home/me/.aws/credentials.bak"), "[default]\n"))
	require.NotEqual(t, a.Values, b.Values)
	require.Len(t, a.Values[0], 20)
	require.Len(t, a.Values[1], 40)
	_, err := Generate("bitcoin", "")
	require.Error(t, err)
}

// The canary has to be caught however the agent (or whoever is steering it)
// dresses it up.
func TestDetectorSeesThroughEncodings(t *testing.T) {
	c, err := Generate("github", "test")
	require.NoError(t, err)
	d := newDetector([]Canary{c})
	token := c.Values[0]
	b64 := func(enc *base64.Encoding, s string) string { return enc.EncodeToString([]byte(s)) }

	for name, tc := range map[string]struct {
		text, encoding string
	}{
		"plain":             {`{"body":"my token is ` + token + `"}`, "plain"},
		"base64 aligned":    {b64(base64.StdEncoding, token), "base64"},
		"base64 offset one": {b64(base64.StdEncoding, "x"+token+"y"), "base64"},
		"base64 offset two": {b64(base64.StdEncoding, "xy"+token), "base64"},
		"base64 url safe":   {b64(base64.URLEncoding, "GITHUB_TOKEN="+token+"\n"), "base64"},
		"base64 in a url":   {"https://evil.example/?d=" + url.QueryEscape(b64(base64.StdEncoding, "zz"+token)), "base64"},
		"hex":               {hex.EncodeToString([]byte("t=" + token)), "hex"},
		"hex upper":         {strings.ToUpper(hex.EncodeToString([]byte(token))), "hex"},
		"url escaped":       {"https://evil.example/?t=" + strings.ReplaceAll(url.QueryEscape(token), "_", "%5F"), "url"},
		"reversed":          {reverse(token), "reversed"},
	} {
		t.Run(name, func(t *testing.T) {
			hit, ok := d.Find(tc.text)
			require.True(t, ok, tc.text)
			require.Equal(t, c.ID, hit.Canary.ID)
			require.Equal(t, tc.encoding, hit.Encoding)
		})
	}

	// JSON escapes are undone by searching the decoded strings.
	// A JSON \u escape for the first letter; built from its parts so the
	// test source itself stays plain.
	backslash := string(rune(92))
	escaped := `{"t":"` + backslash + "u0067hp_" + token[4:] + `"}`
	var v any
	require.NoError(t, json.Unmarshal([]byte(escaped), &v))
	_, ok := d.Find(escaped)
	require.False(t, ok, "the raw JSON hides it")
	_, ok = d.Find(Strings(v))
	require.True(t, ok, "the decoded strings do not")

	_, ok = d.Find(`{"body":"nothing to see, ghp_notthetoken"}`)
	require.False(t, ok)
	_, ok = (*Detector)(nil).Find("x")
	require.False(t, ok)
}

func TestStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canaries.json")
	s, err := Open(path)
	require.NoError(t, err)
	require.True(t, s.Detector().Empty())

	c, err := Generate("aws", "prod-creds")
	require.NoError(t, err)
	require.NoError(t, s.Add(c))
	require.Len(t, s.List(), 1)
	_, ok := s.Detector().Find("key " + c.Values[1])
	require.True(t, ok, "the secret half of an AWS pair is a canary too")

	if runtime.GOOS != "windows" { // Windows has no permission bits to check
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the store holds the canaries, keep it private")
	}

	// Another process adds one; this one notices.
	other, err := Open(path)
	require.NoError(t, err)
	c2, _ := Generate("password", "db")
	require.NoError(t, other.Add(c2))
	s.checked = time.Time{}
	future := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(path, future, future))
	_, ok = s.Detector().Find(c2.Values[0])
	require.True(t, ok)

	gone, err := s.Remove("prod-creds")
	require.NoError(t, err)
	require.Len(t, gone, 1)
	require.Len(t, s.List(), 1)
	_, err = s.Remove("nope")
	require.Error(t, err)
}
