package appviewdb

import (
	"context"
	"path/filepath"
	"testing"
)

func TestNewCommentsReadsFeedComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "appview.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// The columns the appview's comments table has in production.
	if _, err := d.sql.Exec(`CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT, collection TEXT, rkey TEXT, cid TEXT,
		subject_uri TEXT, subject_cid TEXT, body_text TEXT, body_original TEXT, body_blobs TEXT, created TEXT,
		reply_to_uri TEXT, reply_to_cid TEXT, pull_round_idx INTEGER, edited TEXT, deleted TEXT)`); err != nil {
		t.Fatal(err)
	}
	const watched = "at://did:plc:bridge/sh.tangled.repo.issue/1"
	rows := []struct {
		did, coll, rkey, subject, body string
		deleted                        any
	}{
		{"did:plc:a", "sh.tangled.feed.comment", "r1", watched, "premier", nil},
		{"did:plc:b", "sh.tangled.feed.comment", "r2", "at://did:plc:other/sh.tangled.repo.issue/9", "autre issue", nil},
		{"did:plc:c", "sh.tangled.feed.comment", "r3", watched, "supprimé", "2026-09-15"},
		{"did:plc:d", "sh.tangled.feed.comment", "r4", watched, "second", nil},
	}
	for _, r := range rows {
		if _, err := d.sql.Exec(`INSERT INTO comments (did, collection, rkey, subject_uri, body_text, deleted) VALUES (?, ?, ?, ?, ?, ?)`,
			r.did, r.coll, r.rkey, r.subject, r.body, r.deleted); err != nil {
			t.Fatal(err)
		}
	}
	got, err := d.NewComments(context.Background(), 0, []string{watched})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Body != "premier" || got[1].Body != "second" {
		t.Fatalf("got %+v", got)
	}
	if got[0].AtURI != "at://did:plc:a/sh.tangled.feed.comment/r1" || got[0].IssueAt != watched {
		t.Fatalf("bad first comment: %+v", got[0])
	}
	if later, _ := d.NewComments(context.Background(), got[0].ID, []string{watched}); len(later) != 1 {
		t.Fatalf("cursor not honoured: %+v", later)
	}
}
