package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"grafttangled/internal/ap"
	"grafttangled/internal/appviewdb"
	"grafttangled/internal/graft"
	"grafttangled/internal/state"
	"grafttangled/internal/tangled"
)

// graftAPI is the subset of the Graft client the bridge needs.
type graftAPI interface {
	Outbox(ctx context.Context, series string) (*ap.OrderedCollection, error)
	ReplyToIssue(ctx context.Context, series, noteURI, content, sourceURL string) error
}

// tangledAPI is the subset of the Tangled client the bridge needs.
type tangledAPI interface {
	DID() string
	CreateRepo(ctx context.Context, in tangled.CreateRepoInput) (tangled.CreateRepoResult, error)
	CreateIssue(ctx context.Context, repoDid, title, body string) (atURI string, err error)
	CreateComment(ctx context.Context, issueAtURI, body string) (atURI string, err error)
}

// SeriesConfig is one federated series the bridge mirrors to Tangled.
type SeriesConfig struct {
	Series      string
	Knot        string // knot hostname to host this series' Tangled repo on
	Source      string // git clone URL the knot imports from (a Forgejo mirror)
	Description string
}

// Options are the bridge's runtime knobs.
type Options struct {
	MaxContentRunes      int
	MaxDeliveriesPerPass int
}

// Bridge mirrors Graft-federated repos to Tangled, both directions:
// Graft issue notes become Tangled issues (auto-creating the repo on
// first use); new comments on those Tangled issues are relayed back to
// Graft as signed replies.
type Bridge struct {
	GraftHost string
	Series    []SeriesConfig
	Opts      Options

	Graft     graftAPI
	Tangled   tangledAPI
	AppviewDB *appviewdb.DB
	// WebURL is the Tangled web UI base URL trackback links point at.
	WebURL string
	State  *state.State
	Log    *slog.Logger
}

// RunOnce performs one full reconciliation pass.
func (b *Bridge) RunOnce(ctx context.Context) error {
	if err := b.forwardGraftToTangled(ctx); err != nil {
		return err
	}
	return b.reverseTangledToGraft(ctx)
}

// ensureRepo returns the series' Tangled repo, creating it on first use.
func (b *Bridge) ensureRepo(ctx context.Context, sc SeriesConfig) (state.RepoInfo, error) {
	if r, ok := b.State.Repo(sc.Series); ok {
		return r, nil
	}
	rkey := sanitizeRkey(sc.Series)
	res, err := b.Tangled.CreateRepo(ctx, tangled.CreateRepoInput{
		Knot:          sc.Knot,
		Rkey:          rkey,
		Name:          sc.Series,
		DefaultBranch: "main",
		Source:        sc.Source,
		Description:   sc.Description,
	})
	if err != nil {
		return state.RepoInfo{}, fmt.Errorf("create tangled repo for series %s: %w", sc.Series, err)
	}
	if err := b.AppviewDB.InsertRepo(ctx, b.Tangled.DID(), sc.Series, sc.Knot, rkey, res.AtURI, res.RepoDid, sc.Source, sc.Description); err != nil {
		b.logf(slog.LevelWarn, "local index insert for new repo failed (repo still created on Tangled)", "series", sc.Series, "err", err)
	}
	info := state.RepoInfo{Knot: sc.Knot, RepoDid: res.RepoDid, AtURI: res.AtURI, Rkey: rkey}
	if err := b.State.SetRepo(sc.Series, info); err != nil {
		return state.RepoInfo{}, err
	}
	b.logf(slog.LevelInfo, "created tangled repo", "series", sc.Series, "repoDid", res.RepoDid)
	return info, nil
}

// forwardGraftToTangled mirrors new issue/patch notes from each configured
// series' Graft outbox as Tangled issues.
func (b *Bridge) forwardGraftToTangled(ctx context.Context) error {
	for _, sc := range b.Series {
		oc, err := b.Graft.Outbox(ctx, sc.Series)
		if err != nil {
			b.logf(slog.LevelError, "graft outbox failed; skipping series", "series", sc.Series, "err", err)
			continue
		}
		notes := graft.ParseNotes(b.GraftHost, oc)

		// Every configured series gets its Tangled repo up front, not
		// only once it has an issue to mirror: a series with git content
		// but no issues yet (e.g. federation-x, graft-presentation) would
		// otherwise never appear on Tangled at all, even though "push
		// their events (commits, issues...)" was the whole point.
		repo, repoErr := b.ensureRepo(ctx, sc)
		if repoErr != nil {
			b.logf(slog.LevelError, "cannot mirror series: repo unavailable", "series", sc.Series, "err", repoErr)
			continue
		}

		for _, n := range notes {
			if !n.IsIssueOrPatch() {
				continue
			}
			if b.State.SeenNote(n.URI) {
				continue
			}

			body := n.URL
			if body == "" {
				body = "mirrored from " + sc.Series
			}
			issueURI, err := b.Tangled.CreateIssue(ctx, repo.RepoDid, n.Summary, body)
			if err != nil {
				b.logf(slog.LevelError, "create tangled issue failed", "series", sc.Series, "note", n.URI, "err", err)
				continue
			}
			rkey := rkeyFromURI(issueURI)
			if _, err := b.AppviewDB.InsertIssue(ctx, b.Tangled.DID(), rkey, repo.RepoDid, n.Summary, body); err != nil {
				b.logf(slog.LevelWarn, "local index insert for new issue failed (issue still created on Tangled)", "note", n.URI, "err", err)
			}
			if err := b.State.LinkIssue(n.URI, issueURI); err != nil {
				return err
			}
			if err := b.State.MarkSeenNote(n.URI); err != nil {
				return err
			}
			b.logf(slog.LevelInfo, "mirrored graft issue to tangled", "series", sc.Series, "note", n.URI, "issue", issueURI)
		}
	}
	return nil
}

// reverseTangledToGraft relays new comments on our bridged Tangled issues
// back to Graft as signed replies.
func (b *Bridge) reverseTangledToGraft(ctx context.Context) error {
	issueURIs := b.State.WatchedIssues()
	if len(issueURIs) == 0 {
		return nil
	}
	cursor := b.State.CommentCursor()
	comments, err := b.AppviewDB.NewComments(ctx, cursor, issueURIs)
	if err != nil {
		return fmt.Errorf("read new tangled comments: %w", err)
	}

	delivered := 0
	// The cursor only moves past comments that are fully dealt with. A
	// failed delivery (graft briefly unreachable, say) or the per-pass
	// limit freezes it there, so those comments are read again next pass;
	// ones already relayed are skipped by their delivered hash, never sent
	// twice.
	maxID := cursor
	frozen := false
	advance := func(id int64) {
		if !frozen && id > maxID {
			maxID = id
		}
	}
	for _, c := range comments {
		if c.DID == b.Tangled.DID() {
			// Our own comment (from the graft->tangled reverse-mirror
			// path below, if that's ever added) — never relay it back,
			// that would loop.
			advance(c.ID)
			continue
		}
		noteURI, ok := b.State.NoteForIssue(c.IssueAt)
		if !ok {
			advance(c.ID)
			continue
		}
		hash := hashContent(c.AtURI)
		if b.State.IsDelivered(hash) {
			advance(c.ID)
			continue
		}
		if b.Opts.MaxDeliveriesPerPass > 0 && delivered >= b.Opts.MaxDeliveriesPerPass {
			b.logf(slog.LevelWarn, "delivery rate limit reached for this pass", "limit", b.Opts.MaxDeliveriesPerPass)
			break
		}
		series, _, ok := ap.ParseNoteURI(b.GraftHost, noteURI)
		if !ok {
			advance(c.ID)
			continue
		}
		content := truncateRunes("**via Tangled, "+c.DID+":**\n\n"+c.Body, b.maxContent())
		if err := b.Graft.ReplyToIssue(ctx, series, noteURI, content, b.commentURL(ctx, c)); err != nil {
			b.logf(slog.LevelError, "deliver tangled comment to graft failed", "comment", c.AtURI, "err", err)
			frozen = true
			continue
		}
		if err := b.State.MarkDelivered(hash); err != nil {
			return err
		}
		advance(c.ID)
		delivered++
		b.logf(slog.LevelInfo, "relayed tangled comment to graft", "comment", c.AtURI, "note", noteURI)
	}
	if maxID > cursor {
		if err := b.State.SetCommentCursor(maxID); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bridge) maxContent() int {
	if b.Opts.MaxContentRunes <= 0 {
		return 8000
	}
	return b.Opts.MaxContentRunes
}

func (b *Bridge) logf(level slog.Level, msg string, args ...any) {
	if b.Log != nil {
		b.Log.Log(context.Background(), level, msg, args...)
	}
}

func hashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// sanitizeRkey turns a series name into a valid AT Proto record key
// (Tangled repo rkeys double as the repo's URL slug): lowercase,
// alphanumeric and hyphens only.
func sanitizeRkey(series string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(series) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// rkeyFromURI extracts the record key (the last path segment) from an
// AT-URI, e.g. "at://did:plc:x/sh.tangled.repo.issue/3jz...".
func rkeyFromURI(atURI string) string {
	i := strings.LastIndex(atURI, "/")
	if i < 0 {
		return atURI
	}
	return atURI[i+1:]
}

// commentURL is the trackback Graft shows next to a relayed Tangled
// comment: the comment's issue page on the Tangled web UI. A Tangled
// comment is a sh.tangled.repo.issue.comment record, not a Bluesky post,
// so there is no bsky.app permalink for it. Empty (no trackback) when no
// web URL is configured or the issue can't be resolved.
func (b *Bridge) commentURL(ctx context.Context, c appviewdb.Comment) string {
	if b.WebURL == "" || b.AppviewDB == nil {
		return ""
	}
	owner, repo, issueID, ok, err := b.AppviewDB.IssueLocation(ctx, c.IssueAt)
	if err != nil {
		b.logf(slog.LevelWarn, "resolve trackback for tangled comment", "comment", c.AtURI, "err", err)
		return ""
	}
	if !ok {
		return ""
	}
	return issueWebURL(b.WebURL, owner, repo, issueID)
}

func issueWebURL(webURL, ownerDID, repoName string, issueID int64) string {
	return fmt.Sprintf("%s/%s/%s/issues/%d", strings.TrimRight(webURL, "/"), ownerDID, url.PathEscape(repoName), issueID)
}
