package graft

import (
	"strings"
	"unicode"

	"grafttangled/internal/ap"
)

// NoteInfo is one mirrored Graft event decoded from a series outbox.
type NoteInfo struct {
	EntryID int64
	URI     string // the note's canonical URI, used as inReplyTo
	Kind    string // "git", "issue", "patch", "comment", or the raw kind
	Summary string
	URL     string // web URL of the underlying issue/PR/commit
}

// IsIssueOrPatch reports whether Graft accepts a reply to this note as a
// comment. Graft's inbox drops replies to anything else (notably commits).
func (n NoteInfo) IsIssueOrPatch() bool {
	return n.Kind == "issue" || n.Kind == "patch"
}

// IssueRef is a discoverable, replyable Graft issue/patch, surfaced to
// operators so they can pick a note URI without guessing.
type IssueRef struct {
	Series  string `json:"series"`
	EntryID int64  `json:"entry_id"`
	Kind    string `json:"kind"`
	Title   string `json:"title"`
	NoteURI string `json:"note_uri"`
	URL     string `json:"url,omitempty"`
}

// ParseNotes decodes the notes in a series outbox. host is the Graft host
// (used to recover each note's activity_log id).
func ParseNotes(host string, col *ap.OrderedCollection) []NoteInfo {
	out := make([]NoteInfo, 0, len(col.OrderedItems))
	for _, item := range col.OrderedItems {
		note := item.Object
		series, id, ok := ap.ParseNoteURI(host, note.ID)
		if !ok || series == "" {
			continue
		}
		kind, summary := splitKind(note.Content)
		out = append(out, NoteInfo{
			EntryID: id,
			URI:     note.ID,
			Kind:    kind,
			Summary: summary,
			URL:     note.URL,
		})
	}
	return out
}

// splitKind turns a Graft note's Content ("Issue: title", "comment: ...")
// into a normalized kind and the remainder.
func splitKind(content string) (kind, summary string) {
	prefix, rest, found := strings.Cut(content, ": ")
	if !found {
		return strings.ToLower(strings.TrimSpace(content)), ""
	}
	switch strings.TrimSpace(prefix) {
	case "Commit":
		kind = "git"
	case "Issue":
		kind = "issue"
	case "Patch":
		kind = "patch"
	default:
		kind = strings.ToLower(strings.TrimSpace(prefix))
	}
	return kind, strings.TrimSpace(rest)
}

// NormalizeTitle lowercases, strips punctuation and collapses whitespace so
// a Discourse topic title can be matched against a Graft issue summary.
func NormalizeTitle(s string) string {
	var b strings.Builder
	lastSpace := true
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastSpace = false
		case unicode.IsSpace(r):
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		default:
			// drop punctuation
		}
	}
	return strings.TrimSpace(b.String())
}

// MatchIssueByTitle returns the first issue note whose normalized summary
// equals the normalized title. The caller is responsible for caching the
// result so the match survives later title edits on either side.
func MatchIssueByTitle(notes []NoteInfo, title string) (NoteInfo, bool) {
	want := NormalizeTitle(title)
	for _, n := range notes {
		if n.Kind == "issue" && NormalizeTitle(n.Summary) == want {
			return n, true
		}
	}
	return NoteInfo{}, false
}
