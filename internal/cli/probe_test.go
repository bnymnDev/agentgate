package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArgsFromSchema(t *testing.T) {
	got := argsFromSchema(json.RawMessage(`{"type":"object","required":["url","limit","kind","tags","opts","path","flag"],
		"properties":{"url":{"type":"string"},"limit":{"type":"integer","minimum":5},"kind":{"enum":["news","blog"]},
		"tags":{"type":"array","minItems":1,"items":{"type":"string"}},"opts":{"type":"object","required":["q"],"properties":{"q":{"type":"string","default":"x"}}},
		"path":{"type":["string","null"]},"flag":{"type":"boolean"},"ignored":{"type":"string"}}}`))
	require.Equal(t, map[string]any{
		"url": "https://example.com/", "limit": 5.0, "kind": "news", "tags": []any{"agentgate"},
		"opts": map[string]any{"q": "x"}, "path": ".", "flag": false,
	}, got)
}
