package graft

import (
	"testing"

	"grafttangled/internal/ap"
)

func TestParseNotes(t *testing.T) {
	col := &ap.OrderedCollection{
		OrderedItems: []ap.Create{
			{Object: ap.Note{
				ID:      ap.NoteURI("g.example", "fedx", 7),
				Content: "Issue: Fix the flux capacitor",
				URL:     "https://g.example/fedx/issues/7",
			}},
			{Object: ap.Note{
				ID:      ap.NoteURI("g.example", "fedx", 8),
				Content: "Commit: bump deps",
			}},
			{Object: ap.Note{
				ID:      ap.NoteURI("g.example", "fedx", 9),
				Content: "comment: looks good to me",
			}},
			{Object: ap.Note{ID: "https://other.example/actors/x/notes/1", Content: "Issue: nope"}},
		},
	}
	notes := ParseNotes("g.example", col)
	if len(notes) != 3 {
		t.Fatalf("got %d notes, want 3: %+v", len(notes), notes)
	}
	if notes[0].Kind != "issue" || notes[0].EntryID != 7 || notes[0].Summary != "Fix the flux capacitor" {
		t.Fatalf("issue note mis-parsed: %+v", notes[0])
	}
	if notes[1].Kind != "git" {
		t.Fatalf("commit kind = %q, want git", notes[1].Kind)
	}
	if notes[2].Kind != "comment" {
		t.Fatalf("comment kind = %q", notes[2].Kind)
	}
}

func TestMatchIssueByTitle(t *testing.T) {
	notes := []NoteInfo{
		{Kind: "git", Summary: "Fix the flux capacitor"},
		{Kind: "issue", Summary: "Fix the Flux Capacitor!"},
		{Kind: "issue", Summary: "Add time machine"},
	}
	if n, ok := MatchIssueByTitle(notes, "  fix the flux   capacitor "); !ok || n.Summary != "Fix the Flux Capacitor!" {
		t.Fatalf("title match failed: %+v ok=%v", n, ok)
	}
	if _, ok := MatchIssueByTitle(notes, "unrelated"); ok {
		t.Fatal("matched an unrelated title")
	}
}

func TestIsIssueOrPatch(t *testing.T) {
	if !(NoteInfo{Kind: "issue"}).IsIssueOrPatch() || !(NoteInfo{Kind: "patch"}).IsIssueOrPatch() {
		t.Fatal("issue/patch should be replyable")
	}
	if (NoteInfo{Kind: "git"}).IsIssueOrPatch() || (NoteInfo{Kind: "comment"}).IsIssueOrPatch() {
		t.Fatal("git/comment must not be replyable")
	}
}
