// Package passkey signs approvals with passkeys (WebAuthn). A click in the
// web UI says that someone at this machine clicked; a passkey assertion says
// that the person holding the authenticator — a phone, a security key, the
// laptop's fingerprint reader — looked at this exact question and answered
// it. The challenge the authenticator signs is a hash of the approval's id,
// the answer and the call's arguments, so the signature is bound to the
// decision it records, and nothing a program on the machine can produce
// without the authenticator.
//
// Enrolling a passkey takes a one-time code that agentgate passkey enroll
// prints in a terminal, so a program that can reach the web UI cannot add a
// passkey of its own. A program that can rewrite agentgate's files can do
// anything; keep the agent away from them.
package passkey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Record is one enrolled passkey.
type Record struct {
	Name       string              `json:"name"`
	Credential webauthn.Credential `json:"credential"`
	CreatedAt  time.Time           `json:"created_at"`
	LastUsed   time.Time           `json:"last_used,omitzero"`
}

// file is what the passkey file holds.
type file struct {
	UserID  []byte   `json:"user_id"`
	Records []Record `json:"passkeys"`
	// Enroll is the hash of the one-time code that allows the next
	// enrolment, and when it expires.
	EnrollHash    string    `json:"enroll_hash,omitempty"`
	EnrollExpires time.Time `json:"enroll_expires,omitzero"`
}

// Store keeps the passkeys in a JSON file.
type Store struct {
	mu   sync.Mutex
	path string
}

// Open returns the store at path; the file is created on first write.
func Open(path string) *Store { return &Store{path: path} }

// Path is where the passkeys are kept.
func (s *Store) Path() string { return s.path }

func (s *Store) load() (*file, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		id := make([]byte, 32)
		_, _ = rand.Read(id)
		return &file{UserID: id}, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	return &f, nil
}

func (s *Store) save(f *file) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// List returns the enrolled passkeys.
func (s *Store) List() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	return f.Records, nil
}

// NewEnrollCode makes the one-time code the next enrolment needs.
func (s *Store) NewEnrollCode(valid time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return "", err
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	code := strings.ToUpper(hex.EncodeToString(b))
	code = code[:4] + "-" + code[4:8] + "-" + code[8:]
	f.EnrollHash, f.EnrollExpires = hashCode(code), time.Now().Add(valid)
	return code, s.save(f)
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return hex.EncodeToString(sum[:])
}

// Remove deletes a passkey by name.
func (s *Store) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	kept := f.Records[:0]
	for _, r := range f.Records {
		if r.Name != name {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(f.Records) {
		return fmt.Errorf("no passkey named %q", name)
	}
	f.Records = kept
	return s.save(f)
}

// user is the one account agentgate knows: whoever approves.
type user struct{ f *file }

func (u user) WebAuthnID() []byte          { return u.f.UserID }
func (u user) WebAuthnName() string        { return "agentgate" }
func (u user) WebAuthnDisplayName() string { return "agentgate approver" }
func (u user) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, len(u.f.Records))
	for i, r := range u.f.Records {
		out[i] = r.Credential
	}
	return out
}

// Service runs enrolments and signed approvals.
type Service struct {
	store *Store
	wa    *webauthn.WebAuthn

	mu       sync.Mutex
	sessions map[string]pending
}

type pending struct {
	data    webauthn.SessionData
	name    string
	expires time.Time
}

// NewService builds a service for the web UI at the given origins, such as
// http://localhost:7777. The relying party is localhost: open the UI at
// localhost, not at 127.0.0.1, where browsers refuse passkeys.
func NewService(store *Store, rpID string, origins []string) (*Service, error) {
	if rpID == "" {
		rpID = "localhost"
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: "agentgate", RPOrigins: origins})
	if err != nil {
		return nil, err
	}
	return &Service{store: store, wa: wa, sessions: map[string]pending{}}, nil
}

// Store is where the service keeps the passkeys.
func (s *Service) Store() *Store { return s.store }

func (s *Service) remember(key string, p pending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[key] = p
}

func (s *Service) take(key string) (pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.sessions[key]
	delete(s.sessions, key)
	if ok && time.Now().After(p.expires) {
		return p, false
	}
	return p, ok
}

// ErrBadCode is an enrolment code that is wrong or expired.
var ErrBadCode = errors.New("the enrolment code is wrong or expired; agentgate passkey enroll prints a new one")

// BeginEnroll starts an enrolment, if the code is right, and returns the
// options for navigator.credentials.create.
func (s *Service) BeginEnroll(name, code string) (*protocol.CredentialCreation, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", errors.New("give the passkey a name, such as the device it is on")
	}
	s.store.mu.Lock()
	f, err := s.store.load()
	s.store.mu.Unlock()
	if err != nil {
		return nil, "", err
	}
	if f.EnrollHash == "" || time.Now().After(f.EnrollExpires) || hashCode(code) != f.EnrollHash {
		return nil, "", ErrBadCode
	}
	for _, r := range f.Records {
		if r.Name == name {
			return nil, "", fmt.Errorf("a passkey named %q exists already", name)
		}
	}
	opts, data, err := s.wa.BeginRegistration(user{f}, webauthn.WithExclusions(webauthn.Credentials(user{f}.WebAuthnCredentials()).CredentialDescriptors()))
	if err != nil {
		return nil, "", err
	}
	key := randomKey()
	s.remember("enroll:"+key, pending{data: *data, name: name, expires: time.Now().Add(5 * time.Minute)})
	return opts, key, nil
}

// FinishEnroll checks the authenticator's answer and keeps the passkey.
func (s *Service) FinishEnroll(key string, body []byte) (string, error) {
	p, ok := s.take("enroll:" + key)
	if !ok {
		return "", errors.New("the enrolment expired; start again")
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return "", err
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	f, err := s.store.load()
	if err != nil {
		return "", err
	}
	if f.EnrollHash == "" {
		return "", ErrBadCode
	}
	cred, err := s.wa.CreateCredential(user{f}, p.data, parsed)
	if err != nil {
		return "", err
	}
	f.Records = append(f.Records, Record{Name: p.name, Credential: *cred, CreatedAt: time.Now().UTC()})
	// The code is good for one passkey.
	f.EnrollHash, f.EnrollExpires = "", time.Time{}
	return p.name, s.store.save(f)
}

// Challenge is what an approval's authenticator signs: the approval, the
// answer and the arguments, hashed together.
func Challenge(approvalID, answer string, args []byte) []byte {
	h := sha256.New()
	for _, part := range [][]byte{[]byte("agentgate approval v1"), []byte(approvalID), []byte(answer), args} {
		h.Write([]byte{0})
		h.Write(part)
	}
	return h.Sum(nil)
}

// BeginSign starts signing an answer to an approval.
func (s *Service) BeginSign(approvalID, answer string, args []byte) (*protocol.CredentialAssertion, error) {
	s.store.mu.Lock()
	f, err := s.store.load()
	s.store.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if len(f.Records) == 0 {
		return nil, errors.New("no passkey is enrolled; agentgate passkey enroll, then the Passkeys page")
	}
	opts, data, err := s.wa.BeginLogin(user{f}, webauthn.WithChallenge(Challenge(approvalID, answer, args)),
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, err
	}
	s.remember("sign:"+approvalID+":"+answer, pending{data: *data, expires: time.Now().Add(2 * time.Minute)})
	return opts, nil
}

// Signed is a verified answer.
type Signed struct {
	// Name is the passkey's name.
	Name string
	// Credential is the start of the credential id, in hex.
	Credential string
	// Evidence is the hash of the signed assertion, for the audit log.
	Evidence string
}

// FinishSign checks the authenticator's signature over an answer.
func (s *Service) FinishSign(approvalID, answer string, body []byte) (*Signed, error) {
	p, ok := s.take("sign:" + approvalID + ":" + answer)
	if !ok {
		return nil, errors.New("this signature request expired; answer again")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, err
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	f, err := s.store.load()
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.ValidateLogin(user{f}, p.data, parsed)
	if err != nil {
		return nil, err
	}
	var name string
	for i, r := range f.Records {
		if string(r.Credential.ID) == string(cred.ID) {
			f.Records[i].Credential.Authenticator.SignCount = cred.Authenticator.SignCount
			f.Records[i].LastUsed = time.Now().UTC()
			name = r.Name
		}
	}
	if err := s.store.save(f); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	id := hex.EncodeToString(cred.ID)
	return &Signed{Name: name, Credential: id[:min(12, len(id))], Evidence: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func randomKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
