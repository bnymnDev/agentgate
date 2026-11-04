package anchor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// OTS stamps statements with OpenTimestamps: the statement's hash goes to
// public calendars, which commit it to the Bitcoin blockchain within hours.
// The proof is kept next to the statement as anchor-<seq>.json.ots; once
// the calendars have committed, `ots upgrade` completes it and `ots verify`
// shows the block that dates it, without trusting agentgate or this machine.
type OTS struct {
	Dir       string
	Calendars []string
	Client    *http.Client
}

func (o OTS) String() string { return "OpenTimestamps into " + o.Dir }

// otsMagic opens every detached timestamp file.
var otsMagic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

const (
	otsVersion = 0x01
	otsSHA256  = 0x08
	otsFork    = 0xff
)

// Publish stamps the statement and writes it and its proof to Dir.
func (o OTS) Publish(ctx context.Context, s Statement) (string, error) {
	line := s.Line()
	sum := digest(line)
	var proofs [][]byte
	var errs []error
	for _, cal := range o.Calendars {
		p, err := o.submit(ctx, cal, sum[:])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		proofs = append(proofs, p)
	}
	if len(proofs) == 0 {
		return "", fmt.Errorf("no calendar took the timestamp: %w", errors.Join(errs...))
	}
	if err := os.MkdirAll(o.Dir, 0o750); err != nil {
		return "", err
	}
	name := filepath.Join(o.Dir, fmt.Sprintf("anchor-%d.json", s.Seq))
	if err := os.WriteFile(name, line, 0o640); err != nil {
		return "", err
	}
	if err := os.WriteFile(name+".ots", otsFile(sum[:], proofs), 0o640); err != nil {
		return "", err
	}
	return name + ".ots", nil
}

func (o OTS) submit(ctx context.Context, calendar string, sum []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(calendar, "/")+"/digest", bytes.NewReader(sum))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Set("User-Agent", "agentgate")
	client := o.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK || len(body) == 0 {
		return nil, fmt.Errorf("%s answered %s", calendar, resp.Status)
	}
	return body, nil
}

// otsFile is a detached timestamp: header, the hash of the stamped file and
// the calendars' answers, each a timestamp on that hash. More than one
// answer is a fork, every branch but the last marked with 0xff.
func otsFile(sum []byte, proofs [][]byte) []byte {
	var b bytes.Buffer
	b.Write(otsMagic)
	b.WriteByte(otsVersion)
	b.WriteByte(otsSHA256)
	b.Write(sum)
	for i, p := range proofs {
		if i < len(proofs)-1 {
			b.WriteByte(otsFork)
		}
		b.Write(p)
	}
	return b.Bytes()
}
