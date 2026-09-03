// Package audit persists sessions and tool calls in a local SQLite database.
//
// Writes are asynchronous and best effort by design: a slow or broken audit
// store must never delay or fail a tool call. Records that cannot be queued are
// counted and logged, never retried in the request path.
package audit

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"

	_ "modernc.org/sqlite" // pure Go driver, no cgo
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// queueSize is how many pending records are buffered before new ones are
// dropped. Sized so that a burst of calls never blocks the proxy.
const queueSize = 512

// Store is the audit database.
type Store struct {
	db       *sql.DB
	log      *slog.Logger
	redactor *Redactor
	maxBytes int

	queue   chan func(context.Context)
	wg      sync.WaitGroup
	closing chan struct{}
	once    sync.Once
	dropped atomic.Int64
}

// Options configure a Store.
type Options struct {
	// Path is the database file. The parent directory is created if missing.
	Path string
	// Redactor is applied to arguments and results before they are stored.
	Redactor *Redactor
	// MaxResultBytes caps a stored result. Zero means unlimited.
	MaxResultBytes int
	// Retention deletes sessions older than this on Open. Zero keeps forever.
	Retention time.Duration
	Logger    *slog.Logger
	// ReadOnly opens an existing database without running migrations or the
	// retention job; used by the CLI's reporting commands.
	ReadOnly bool
}

// Open opens (and if needed creates and migrates) the audit database.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Path == "" {
		return nil, errors.New("audit: no database path configured")
	}
	if !opts.ReadOnly {
		if dir := filepath.Dir(opts.Path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("audit: creating %s: %w", dir, err)
			}
		}
	} else if _, err := os.Stat(opts.Path); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	db, err := sql.Open("sqlite", dsn(opts.Path, opts.ReadOnly))
	if err != nil {
		return nil, fmt.Errorf("audit: opening %s: %w", opts.Path, err)
	}
	// SQLite tolerates exactly one writer; a single connection removes lock
	// contention entirely and the query volume here is tiny.
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: opening %s: %w", opts.Path, err)
	}
	s := &Store{
		db:       db,
		log:      opts.Logger,
		redactor: opts.Redactor,
		maxBytes: opts.MaxResultBytes,
		queue:    make(chan func(context.Context), queueSize),
		closing:  make(chan struct{}),
	}
	if !opts.ReadOnly {
		if err := s.migrate(ctx); err != nil {
			db.Close()
			return nil, err
		}
		if opts.Retention > 0 {
			if n, err := s.Prune(ctx, time.Now().Add(-opts.Retention)); err != nil {
				s.log.Warn("audit retention job failed", "error", err)
			} else if n > 0 {
				s.log.Info("audit retention removed old sessions", "sessions", n)
			}
		}
	}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	if readOnly {
		q.Set("mode", "ro")
	}
	return "file:" + path + "?" + q.Encode()
}

// run drains the write queue until Close.
func (s *Store) run() {
	defer s.wg.Done()
	for fn := range s.queue {
		// Writes get their own timeout: they must not inherit the (possibly
		// already cancelled) context of the tool call that produced them.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		fn(ctx)
		cancel()
	}
}

// enqueue schedules a write, dropping it if the queue is full or the store is
// closing. It never blocks.
func (s *Store) enqueue(what string, fn func(context.Context)) {
	if s == nil {
		return
	}
	select {
	case <-s.closing:
		return
	default:
	}
	select {
	case s.queue <- fn:
	default:
		n := s.dropped.Add(1)
		s.log.Warn("audit queue full, record dropped", "record", what, "dropped_total", n)
	}
}

// Dropped reports how many records were dropped because the queue was full.
func (s *Store) Dropped() int64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

// Close flushes pending writes and closes the database. It waits at most until
// ctx is done for the queue to drain.
func (s *Store) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		close(s.closing)
		close(s.queue)
	})
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.log.Warn("audit store closed with writes still pending")
	}
	if n := s.dropped.Load(); n > 0 {
		s.log.Warn("audit records were dropped because the write queue was full", "dropped", n)
	}
	return s.db.Close()
}

// NewID returns a lexicographically sortable ULID, used for session and call
// identifiers. Sorting by id therefore sorts by time.
func NewID() string {
	return ulid.Make().String()
}

// migrate applies every embedded migration that has not run yet.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("audit: creating migration table: %w", err)
	}
	applied := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("audit: reading migration table: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	names, err := migrationNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		version := strings.TrimSuffix(name, ".sql")
		if applied[version] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("audit: migration %s: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			version, time.Now().UnixMilli()); err != nil {
			tx.Rollback()
			return fmt.Errorf("audit: migration %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("audit: migration %s: %w", version, err)
		}
		s.log.Info("applied audit migration", "version", version)
	}
	return nil
}

// SchemaVersion returns the newest migration applied to the database.
func (s *Store) SchemaVersion(ctx context.Context) (string, error) {
	var v sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return "", err
	}
	return v.String, nil
}

func migrationNames() ([]string, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
