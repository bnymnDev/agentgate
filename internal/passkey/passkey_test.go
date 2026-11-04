package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

const origin = "http://localhost:7799"

// softKey is enough of an authenticator for the tests: an ES256 key and
// "none" attestation, the way a browser's platform authenticator answers.
type softKey struct {
	priv   *ecdsa.PrivateKey
	id     []byte
	userID []byte
	count  uint32
}

func newSoftKey(t *testing.T) *softKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softKey{priv: priv, id: id}
}

var b64 = base64.RawURLEncoding

func clientData(typ string, challenge []byte) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": b64.EncodeToString(challenge), "origin": origin, "crossOrigin": false})
	return b
}

func (k *softKey) authData(flags byte, attested bool) []byte {
	rp := sha256.Sum256([]byte("localhost"))
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	k.count++
	out = binary.BigEndian.AppendUint32(out, k.count)
	if attested {
		out = append(out, make([]byte, 16)...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(k.id)))
		out = append(out, k.id...)
		// The uncompressed point is 0x04 || X || Y.
		point, _ := k.priv.PublicKey.Bytes()
		x, y := point[1:33], point[33:65]
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, cose...)
	}
	return out
}

func (k *softKey) register(challenge, userID []byte) []byte {
	k.userID = userID
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(0x45, true)})
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(clientData("webauthn.create", challenge)), "attestationObject": b64.EncodeToString(att)},
	})
	return body
}

func (k *softKey) sign(t *testing.T, challenge []byte) []byte {
	cd := clientData("webauthn.get", challenge)
	ad := k.authData(0x05, false)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(k.userID)},
	})
	return body
}

func setup(t *testing.T) (*Service, *softKey) {
	store := Open(filepath.Join(t.TempDir(), "passkeys.json"))
	svc, err := NewService(store, "localhost", []string{origin})
	require.NoError(t, err)
	code, err := store.NewEnrollCode(time.Minute)
	require.NoError(t, err)

	_, _, err = svc.BeginEnroll("laptop", "0000-0000-0000")
	require.ErrorIs(t, err, ErrBadCode, "no code, no passkey")

	opts, key, err := svc.BeginEnroll("laptop", code)
	require.NoError(t, err)
	k := newSoftKey(t)
	var wire struct {
		PublicKey struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	raw, _ := json.Marshal(opts)
	require.NoError(t, json.Unmarshal(raw, &wire))
	userID, err := b64.DecodeString(wire.PublicKey.User.ID)
	require.NoError(t, err)
	name, err := svc.FinishEnroll(key, k.register(opts.Response.Challenge, userID))
	require.NoError(t, err)
	require.Equal(t, "laptop", name)

	_, _, err = svc.BeginEnroll("second", code)
	require.ErrorIs(t, err, ErrBadCode, "a code is good for one passkey")
	return svc, k
}

func TestEnrolAndSign(t *testing.T) {
	svc, k := setup(t)
	args := []byte(`{"command":"make deploy"}`)
	opts, err := svc.BeginSign("A1", "allow", args)
	require.NoError(t, err)
	require.Equal(t, Challenge("A1", "allow", args), []byte(opts.Response.Challenge), "the signature is bound to the answer")

	signed, err := svc.FinishSign("A1", "allow", k.sign(t, opts.Response.Challenge))
	require.NoError(t, err)
	require.Equal(t, "laptop", signed.Name)
	require.Contains(t, signed.Evidence, "sha256:")

	list, err := svc.Store().List()
	require.NoError(t, err)
	require.False(t, list[0].LastUsed.IsZero())
}

// A signature over another question, or another answer, does not count.
func TestSignatureIsBoundToTheAnswer(t *testing.T) {
	svc, k := setup(t)
	args := []byte(`{"command":"make deploy"}`)
	_, err := svc.BeginSign("A1", "allow", args)
	require.NoError(t, err)
	_, err = svc.FinishSign("A1", "allow", k.sign(t, Challenge("A1", "deny", args)))
	require.Error(t, err, "signed deny, presented as allow")

	_, err = svc.FinishSign("A1", "allow", k.sign(t, Challenge("A1", "allow", args)))
	require.Error(t, err, "a signature request is used up by the first attempt")

	other := newSoftKey(t)
	other.userID = k.userID
	opts, err := svc.BeginSign("A2", "allow", args)
	require.NoError(t, err)
	_, err = svc.FinishSign("A2", "allow", other.sign(t, opts.Response.Challenge))
	require.Error(t, err, "a key nobody enrolled")
}
