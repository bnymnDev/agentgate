package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Canonical re-encodes a JSON document with object keys sorted and no
// insignificant whitespace, so that two structurally equal documents always
// produce the same bytes and therefore the same hash.
func Canonical(raw []byte) []byte {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		// Not JSON: hash the bytes as they are rather than losing the record.
		return raw
	}
	var buf bytes.Buffer
	writeCanonical(&buf, v)
	return buf.Bytes()
}

func writeCanonical(buf *bytes.Buffer, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			writeCanonical(buf, t[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonical(buf, e)
		}
		buf.WriteByte(']')
	default:
		b, err := json.Marshal(v)
		if err != nil {
			buf.WriteString("null")
			return
		}
		buf.Write(b)
	}
}

// Hash returns the sha256 of the canonical form of raw, hex encoded. An empty
// document hashes to the empty string so that "no result" is distinguishable
// from "a result that happened to be empty".
func Hash(raw []byte) string {
	c := Canonical(raw)
	if len(c) == 0 {
		return ""
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:])
}

// TokensEst is the rough token count agentgate reports for budgets and the UI:
// characters divided by four, the usual back-of-the-envelope for English text
// and JSON.
func TokensEst(parts ...[]byte) int {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	return n / 4
}
