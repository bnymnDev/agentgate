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
	"modernc.org/sqlite" // pure Go driver, no cgo
	sqlite3 "modernc.org/sqlite/lib"
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
	} else {
		if _, err := os.Stat(opts.Path); err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		// A database last written by an older agentgate lacks the newest
		// columns, and every query would fail on it. Bring it up to date
		// first; adding columns does not disturb a proxy that is writing to
		// it at the same time.
		if err := upgrade(ctx, opts.Path, opts.Logger); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", dsn(opts.Path, opts.ReadOnly))
	if err != nil {
		return nil, fmt.Errorf("audit: opening %s: %w", opts.Path, err)
	}
	// SQLite tolerates exactly one writer; a single connection removes lock
	// contention entirely and the query volume here is tiny.
	db.SetMaxOpenConns(1)
	if err := retryBusy(ctx, func() error { return db.PingContext(ctx) }); err != nil {
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
		if err := retryBusy(ctx, func() error { return s.migrate(ctx) }); err != nil {
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
	// Writers take the write lock when their transaction begins, not when it
	// first writes: appending to the hash chain reads the head and writes the
	// next link, and no other process may slip a link in between.
	q.Set("_txlock", "immediate")
	if readOnly {
		q.Set("mode", "ro")
	}
	// SQLite URIs want forward slashes even on Windows.
	return "file:" + filepath.ToSlash(path) + "?" + q.Encode()
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
	applied, err := appliedMigrations(ctx, s.db)
	if err != nil {
		return fmt.Errorf("audit: reading migration table: %w", err)
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
		// Another process may have applied it since the list was read; the
		// transaction holds the write lock, so this second look is final.
		var done int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&done); err != nil {
			tx.Rollback()
			return fmt.Errorf("audit: migration %s: %w", version, err)
		}
		if done > 0 {
			tx.Rollback()
			continue
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

// retryBusy runs fn again while SQLite says the database is locked. The busy
// timeout covers most contention, but not all of it: switching a brand-new
// database to WAL, or two processes creating it at the same moment, can
// report "locked" straight away. That happens when several hosts start their
// agentgate at once, and is worth a few quick retries rather than a failed
// start.
func retryBusy(ctx context.Context, fn func() error) error {
	deadline := time.Now().Add(10 * time.Second)
	wait := 10 * time.Millisecond
	for {
		err := fn()
		if err == nil || !isBusy(err) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		wait = min(wait*2, 250*time.Millisecond)
	}
}

func isBusy(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
			return true
		}
	}
	return false
}

// upgrade applies pending migrations to an existing database, and nothing
// else: no retention job, no write queue. A database that is already up to
// date is only read, so this works on one the user cannot write to.
func upgrade(ctx context.Context, path string, log *slog.Logger) error {
	ro, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return fmt.Errorf("audit: opening %s: %w", path, err)
	}
	applied, err := appliedMigrations(ctx, ro)
	ro.Close()
	if err != nil {
		return fmt.Errorf("audit: reading %s: %w", path, err)
	}
	names, err := migrationNames()
	if err != nil {
		return err
	}
	pending := false
	for _, name := range names {
		pending = pending || !applied[strings.TrimSuffix(name, ".sql")]
	}
	if !pending {
		return nil
	}
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return fmt.Errorf("audit: opening %s: %w", path, err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := &Store{db: db, log: log}
	if err := retryBusy(ctx, func() error { return s.migrate(ctx) }); err != nil {
		return fmt.Errorf("%w (the database was written by an older agentgate and could not be upgraded)", err)
	}
	return nil
}

// appliedMigrations lists the migrations a database has had. A database
// without the bookkeeping table has had none.
func appliedMigrations(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	applied := map[string]bool{}
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		return applied, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
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
