// Package appviewdb reads and writes the Tangled appview's own SQLite
// database directly. This bridge runs co-located with the appview
// specifically so this works.
//
// Reading: the appview already indexes every sh.tangled.repo.issue.comment
// record from the public Jetstream firehose (any PDS, any account) into
// this database — a much simpler source of truth for "what new comments
// exist" than running a second firehose consumer here.
//
// Writing: this used to also be motivated by our PDS not being crawled
// by the public AT Proto relay network at all — that's no longer true
// (com.atproto.sync.getHostStatus against relay1.us-west.bsky.network
// now reports status "active" for pds.cyberwild.org, ingesting all 6
// accounts; checked directly, 2026-09-14 — com.atproto.sync.getHost,
// which doesn't exist, 404ing was mistaken for this earlier). The
// dual-write is kept anyway: it's synchronous (the appview reflects our
// own write immediately, no firehose lag to reason about) and doesn't
// depend on the relay's crawl staying healthy. Revisit whether the
// firehose alone is now reliable enough to drop this. The two must be
// kept in sync by hand:
// every field written to the PDS record (client.go) has a matching column
// written here (this file) — see InsertRepo/InsertIssue/InsertComment.
package appviewdb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// DB is a read-write handle on the appview's SQLite database.
type DB struct {
	sql *sql.DB
}

// Open opens path (the appview's appview.db).
func Open(path string) (*DB, error) {
	d, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return nil, err
	}
	if err := d.Ping(); err != nil {
		d.Close()
		return nil, fmt.Errorf("open appview db %s: %w", path, err)
	}
	return &DB{sql: d}, nil
}

func (d *DB) Close() error { return d.sql.Close() }

// Comment is one row from the appview's issue_comments table.
type Comment struct {
	ID      int64
	DID     string // author's DID
	IssueAt string // AT-URI of the issue this comments on
	Body    string
	AtURI   string // this comment's own AT-URI
}

// NewComments returns every issue_comments row with id > sinceID, oldest
// first, whose issue_at is one of issueAtURIs (the issues this bridge
// created and is watching). Soft-deleted comments are excluded.
func (d *DB) NewComments(ctx context.Context, sinceID int64, issueAtURIs []string) ([]Comment, error) {
	if len(issueAtURIs) == 0 {
		return nil, nil
	}
	placeholders := make([]byte, 0, len(issueAtURIs)*2)
	args := make([]any, 0, len(issueAtURIs)+1)
	args = append(args, sinceID)
	for i, uri := range issueAtURIs {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args = append(args, uri)
	}
	query := fmt.Sprintf(`
		SELECT id, did, issue_at, body, at_uri
		FROM issue_comments
		WHERE id > ? AND issue_at IN (%s) AND deleted IS NULL
		ORDER BY id ASC`, string(placeholders))
	rows, err := d.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query new comments: %w", err)
	}
	defer rows.Close()
	var out []Comment
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.DID, &c.IssueAt, &c.Body, &c.AtURI); err != nil {
			return nil, fmt.Errorf("scan comment row: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// InsertRepo mirrors a sh.tangled.repo PDS write into the appview's repos
// table, ignoring a UNIQUE-constraint conflict (the repo was already
// indexed, e.g. by a rare successful firehose delivery — harmless, our PDS
// write is the source of truth either way).
// IssueLocator resolves an issue's AT-URI to the repo rkey and the
// repo-scoped sequential number ("#N") Tangled's own web UI addresses it
// by (/<owner>/<repo>/issues/<N>) — used to build a trackback link for a
// comment relayed back to Graft.
func (d *DB) IssueLocator(ctx context.Context, issueAtURI string) (repoRkey string, issueID int64, err error) {
	row := d.sql.QueryRowContext(ctx, `
		SELECT repos.rkey, issues.issue_id
		FROM issues JOIN repos ON repos.repo_did = issues.repo_did
		WHERE issues.at_uri = ?`, issueAtURI)
	err = row.Scan(&repoRkey, &issueID)
	return repoRkey, issueID, err
}

func (d *DB) InsertRepo(ctx context.Context, did, name, knot, rkey, atURI, repoDid, source, description string) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT OR IGNORE INTO repos (did, name, knot, rkey, at_uri, repo_did, source, description)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		did, name, knot, rkey, atURI, repoDid, nullIfEmpty(source), nullIfEmpty(description))
	if err != nil {
		return fmt.Errorf("insert repo: %w", err)
	}
	return nil
}

// InsertIssue mirrors a sh.tangled.repo.issue PDS write into the appview's
// issues table. issueID (the repo-scoped sequential number Tangled shows
// as "#N") is assigned via the appview's own repo_issue_seqs counter table
// — same insert-or-ignore-then-atomic-increment sequence as its own
// createNewIssue (appview/db/issues.go), copied exactly so a human
// creating an issue through the real Tangled UI afterwards can't collide
// with a number this bridge already used. An earlier version of this
// method computed max(issue_id)+1 locally instead, which desynced from
// repo_issue_seqs (never touched) and produced exactly that collision —
// UNIQUE constraint failed: issues.repo_did, issues.issue_id — the moment
// a real user tried to file a new issue.
func (d *DB) InsertIssue(ctx context.Context, did, rkey, repoDid, title, body string) (issueID int64, err error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO repo_issue_seqs (repo_did, next_issue_id)
		VALUES (?, 1)`, repoDid); err != nil {
		return 0, fmt.Errorf("ensure issue seq: %w", err)
	}
	row := tx.QueryRowContext(ctx, `
		UPDATE repo_issue_seqs
		SET next_issue_id = next_issue_id + 1
		WHERE repo_did = ?
		RETURNING next_issue_id - 1`, repoDid)
	if err := row.Scan(&issueID); err != nil {
		return 0, fmt.Errorf("advance issue seq: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO issues (did, rkey, repo_did, issue_id, title, body, open)
		VALUES (?, ?, ?, ?, ?, ?, 1)`,
		did, rkey, repoDid, issueID, title, body); err != nil {
		return 0, fmt.Errorf("insert issue: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return issueID, nil
}

// InsertComment mirrors a sh.tangled.repo.issue.comment PDS write into the
// appview's issue_comments table.
func (d *DB) InsertComment(ctx context.Context, did, rkey, issueAt, body string) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT OR IGNORE INTO issue_comments (did, rkey, issue_at, body)
		VALUES (?, ?, ?, ?)`,
		did, rkey, issueAt, body)
	if err != nil {
		return fmt.Errorf("insert comment: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
