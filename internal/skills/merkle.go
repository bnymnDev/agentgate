package skills

import (
	"crypto/sha256"
	"encoding/hex"
)

// MerkleRoot is the root of a Merkle tree over a skill's files, in the shape
// of RFC 6962 (Certificate Transparency): a leaf is SHA-256(0x00 || leaf
// data), an inner node is SHA-256(0x01 || left || right), and a tree of n
// leaves splits at the largest power of two below n. The prefixes keep a
// leaf from ever being passed off as a node.
//
// A leaf's data is the file's path, its kind and the hash of its content,
// separated by NUL bytes, so renaming a file changes the root as surely as
// editing it does. files must be sorted by path.
func MerkleRoot(files []File) string {
	leaves := make([][]byte, len(files))
	for i, f := range files {
		leaves[i] = leafHash(f)
	}
	return "sha256:" + hex.EncodeToString(merkle(leaves))
}

func leafHash(f File) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write([]byte(f.Path))
	h.Write([]byte{0})
	h.Write([]byte(f.Kind))
	h.Write([]byte{0})
	h.Write([]byte(f.Hash))
	return h.Sum(nil)
}

func merkle(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		sum := sha256.Sum256(nil)
		return sum[:]
	case 1:
		return leaves[0]
	}
	k := 1
	for k<<1 < len(leaves) {
		k <<= 1
	}
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(merkle(leaves[:k]))
	h.Write(merkle(leaves[k:]))
	return h.Sum(nil)
}
