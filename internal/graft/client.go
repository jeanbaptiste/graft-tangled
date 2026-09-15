package graft

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"grafttangled/internal/ap"
)

// Client talks to one Graft instance's public ActivityPub surface.
type Client struct {
	// BaseURL is the Graft origin, e.g. "https://f1.cyberwild.org".
	BaseURL string
	// ActorURL is the bridge's own actor URL, embedded as the "actor" of
	// every activity we deliver.
	ActorURL string
	// KeyID is the bridge actor's publicKey id, used on the Signature.
	KeyID string
	// HTTP is the client used for every call. It should be SSRF-safe in
	// production (see NewSafeClient).
	HTTP *http.Client
	// Host is the Graft host Graft uses for its own actor URIs. Defaults to
	// the host of BaseURL.
	Host string

	sign     func(*http.Request, []byte) error
	validate func(string) error
}

// Config configures a Client.
type Config struct {
	BaseURL  string
	ActorURL string
	KeyID    string
	HTTP     *http.Client
	// Sign signs an outbound request in place. Injected so the package
	// stays free of key handling; see ap.SignRequest.
	Sign func(*http.Request, []byte) error
	// Validate rejects unsafe remote-supplied URLs (notably an actor's
	// inbox) before we POST to them. See netguard.Options.Validate.
	Validate func(string) error
}

// New builds a Client.
func New(cfg Config) *Client {
	base := strings.TrimRight(cfg.BaseURL, "/")
	httpc := cfg.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{
		BaseURL:  base,
		ActorURL: cfg.ActorURL,
		KeyID:    cfg.KeyID,
		HTTP:     httpc,
		Host:     hostOf(base),
		sign:     cfg.Sign,
		validate: cfg.Validate,
	}
}

func (c *Client) actorURL(series string) string { return c.BaseURL + "/actors/" + series }
func (c *Client) outboxURL(series string) string {
	return c.actorURL(series) + "/outbox"
}

// Actor fetches a series' actor document (for its inbox URL).
func (c *Client) Actor(ctx context.Context, series string) (*ap.Actor, error) {
	var a ap.Actor
	if err := c.getJSON(ctx, c.actorURL(series), &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Outbox fetches a series' recent activity as an OrderedCollection.
func (c *Client) Outbox(ctx context.Context, series string) (*ap.OrderedCollection, error) {
	var oc ap.OrderedCollection
	if err := c.getJSON(ctx, c.outboxURL(series), &oc); err != nil {
		return nil, err
	}
	return &oc, nil
}

// ReplyToIssue delivers a signed Create{Note} to the series inbox whose
// inReplyTo points at issueOrPatchNoteURI. Graft routes it as a comment on
// the underlying Forgejo/Radicle issue or patch.
//
// Deliberately still ActivityPub, not AT Proto, even though everything
// else about this bridge (including the account it authenticates as) is
// AT Proto — considered and rejected. Graft's AT Proto reply path
// (pollSeriesReplies, cmd/sync/bluesky_replies.go) only fires from
// app.bsky.notification.listNotifications' "reply" reason, which AT
// Proto only generates when a reply's reply.parent points at a post
// Graft itself published. Graft posts to Bluesky for patches and git
// pushes (internal/sync/patches.go, git.go) but never for issues — and
// issues are most of what this bridge mirrors. With no Graft-owned
// parent post to reply to for an issue, there is no AT Proto notification
// to detect in the first place, so a native AT Proto reply here would
// silently never reach Graft for the majority of what this bridge
// relays. Revisit if Graft ever posts an AT Proto note per issue too.
func (c *Client) ReplyToIssue(ctx context.Context, series, issueOrPatchNoteURI, content, sourceURL string) error {
	a, err := c.Actor(ctx, series)
	if err != nil {
		return fmt.Errorf("resolve %s actor: %w", series, err)
	}
	if c.validate != nil {
		if err := c.validate(a.Inbox); err != nil {
			return fmt.Errorf("refusing unsafe inbox %q: %w", a.Inbox, err)
		}
	}
	now := time.Now().UTC()
	noteID := fmt.Sprintf("%s/notes/%d", c.ActorURL, now.UnixNano())
	note := ap.Note{
		Context:      "https://www.w3.org/ns/activitystreams",
		ID:           noteID,
		Type:         "Note",
		AttributedTo: c.ActorURL,
		InReplyTo:    issueOrPatchNoteURI,
		Content:      content,
		URL:          sourceURL,
		Published:    now.Format(time.RFC3339),
		To:           []string{ap.PublicAudience},
	}
	create := ap.Create{
		Context:   "https://www.w3.org/ns/activitystreams",
		ID:        noteID + "/activity",
		Type:      "Create",
		Actor:     c.ActorURL,
		Published: note.Published,
		To:        []string{ap.PublicAudience},
		Object:    note,
	}
	body, err := json.Marshal(create)
	if err != nil {
		return err
	}
	return c.postSigned(ctx, a.Inbox, body)
}

func (c *Client) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", ap.ContentType)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("get %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, ap.MaxBody))
		return fmt.Errorf("get %s: HTTP %d: %s", url, resp.StatusCode, truncateForLog(b))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, ap.MaxBody)).Decode(v); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}

func (c *Client) postSigned(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", ap.ContentType)
	if c.sign != nil {
		if err := c.sign(req, body); err != nil {
			return err
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, ap.MaxBody))
		return fmt.Errorf("post %s: HTTP %d: %s", url, resp.StatusCode, truncateForLog(b))
	}
	return nil
}

// truncateForLog bounds how much of a remote response body lands in an
// error string — mirrors ap.PostSigned's own helper, kept local since
// exporting a formatting helper across packages isn't worth the coupling.
func truncateForLog(b []byte) string {
	const max = 500
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "... (truncated)"
}

func hostOf(base string) string {
	s := base
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
