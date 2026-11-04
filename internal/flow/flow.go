// Package flow fingerprints text so that a passage copied from one tool's
// result into another tool's arguments can be recognised, without keeping
// the text itself. It uses winnowing (Schleimer, Wilkerson and Aiken, 2003),
// the algorithm behind plagiarism detectors: hash every k-character window,
// keep the smallest hash of every w consecutive ones. Any passage of at
// least k+w-1 characters that two texts share leaves a common fingerprint,
// whatever surrounds it.
package flow

import (
	"hash/fnv"
	"unicode"
)

const (
	// K is the length of a hashed window.
	K = 16
	// W is how many windows each kept hash is the minimum of.
	W = 9
	// Guaranteed is the shortest shared passage that is always found.
	Guaranteed = K + W - 1
)

// normalize lowercases and collapses every run of space, so a passage is
// found again after it was re-wrapped or re-indented.
func normalize(s string) []rune {
	out := make([]rune, 0, len(s))
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !space && len(out) > 0 {
				out = append(out, ' ')
			}
			space = true
			continue
		}
		space = false
		out = append(out, unicode.ToLower(r))
	}
	return out
}

// Fingerprints returns the winnowed hashes of a text.
func Fingerprints(text string) []uint64 {
	rs := normalize(text)
	if len(rs) < K {
		return nil
	}
	hashes := make([]uint64, 0, len(rs)-K+1)
	h := fnv.New64a()
	for i := 0; i+K <= len(rs); i++ {
		h.Reset()
		_, _ = h.Write([]byte(string(rs[i : i+K])))
		hashes = append(hashes, h.Sum64())
	}
	if len(hashes) <= W {
		return []uint64{minOf(hashes)}
	}
	var out []uint64
	last := -1
	for i := 0; i+W <= len(hashes); i++ {
		// The rightmost minimum, so a run of equal hashes keeps one.
		m := i
		for j := i; j < i+W; j++ {
			if hashes[j] <= hashes[m] {
				m = j
			}
		}
		if m != last {
			out = append(out, hashes[m])
			last = m
		}
	}
	return out
}

func minOf(hs []uint64) uint64 {
	m := hs[0]
	for _, h := range hs[1:] {
		m = min(m, h)
	}
	return m
}

// Set is the fingerprints of everything read from one source, bounded.
type Set struct {
	max int
	m   map[uint64]struct{}
}

// NewSet makes a set that keeps at most max fingerprints; the first ones
// are kept.
func NewSet(max int) *Set { return &Set{max: max, m: map[uint64]struct{}{}} }

// Add adds a text's fingerprints and reports how many were new.
func (s *Set) Add(text string) int {
	n := 0
	for _, f := range Fingerprints(text) {
		if len(s.m) >= s.max {
			break
		}
		if _, ok := s.m[f]; !ok {
			s.m[f] = struct{}{}
			n++
		}
	}
	return n
}

// Shares reports whether a text shares a passage with what the set holds.
func (s *Set) Shares(text string) bool {
	if s == nil || len(s.m) == 0 {
		return false
	}
	for _, f := range Fingerprints(text) {
		if _, ok := s.m[f]; ok {
			return true
		}
	}
	return false
}

// Len is the number of fingerprints held.
func (s *Set) Len() int { return len(s.m) }
