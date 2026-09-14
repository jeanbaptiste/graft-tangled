// Package tangled talks to a Tangled knot and its owning account's PDS
// directly over XRPC/AT Proto — no browser, no OAuth flow. Every write
// Tangled's own web UI makes follows the same two-step shape (see
// tangled.org/core's appview/repo/repo.go, read directly to derive this):
//
//  1. A service-auth token, minted by the account's own PDS
//     (com.atproto.server.getServiceAuth, audience = the knot's did:web),
//     authorizes one call to a knot-side XRPC procedure (e.g.
//     sh.tangled.repo.create).
//  2. The result (e.g. a knot-minted repoDid) gets written back to the
//     account's own PDS as a record (com.atproto.repo.createRecord /
//     putRecord) — the Tangled appview picks it up from there via the
//     public Jetstream firehose it already subscribes to.
//
// Nothing here is Tangled-specific infrastructure: it's the account's own
// PDS plus the knot's XRPC surface, both reachable with a plain HTTP
// client and the account's password.
package tangled

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is authenticated as one bridge bot account and talks to that
// account's own PDS plus whichever knot(s) it creates repos on.
type Client struct {
	PDSBaseURL string // e.g. https://pds.cyberwild.org
	Handle     string // e.g. graft-tangled.pds.cyberwild.org
	HTTP       *http.Client

	did       string
	accessJwt string

	// appPassword and loggedInAt back a session that would otherwise
	// never be refreshed: Login was previously called exactly once at
	// startup, and every subsequent call kept reusing that same
	// accessJwt forever. AT Proto access JWTs expire (commonly within a
	// couple of hours) — confirmed live, where this repeatedly failed
	// every write with ExpiredToken from some point after startup
	// onward, never recovering on its own. ensureFreshSession
	// proactively re-logs-in past sessionMaxAge; doAuthenticated also
	// reacts to an ExpiredToken response directly, in case the PDS's
	// actual token lifetime is shorter than assumed.
	appPassword string
	loggedInAt  time.Time
}

// sessionMaxAge is a conservative bound under AT Proto's actual access
// token lifetime (commonly ~2h for indigo-based PDS implementations, per
// com.atproto.server.createSession) — proactively refreshed before that,
// so a long-idle bridge process never runs purely on the reactive
// ExpiredToken retry path.
const sessionMaxAge = 90 * time.Minute

// Config configures a Client.
type Config struct {
	PDSBaseURL string
	Handle     string
	HTTP       *http.Client
}

func New(cfg Config) *Client {
	h := cfg.HTTP
	if h == nil {
		h = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{PDSBaseURL: cfg.PDSBaseURL, Handle: cfg.Handle, HTTP: h}
}

// Login authenticates against the account's own PDS with an app password.
// The password is kept (not just the resulting session) so
// ensureFreshSession can silently re-authenticate later, on the same
// schedule a human re-typing their password never has to think about.
func (c *Client) Login(ctx context.Context, appPassword string) error {
	c.appPassword = appPassword
	return c.doLogin(ctx)
}

func (c *Client) doLogin(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{
		"identifier": c.Handle,
		"password":   c.appPassword,
	})
	var out struct {
		Did       string `json:"did"`
		AccessJwt string `json:"accessJwt"`
	}
	if err := c.post(ctx, c.PDSBaseURL, "com.atproto.server.createSession", "", body, &out); err != nil {
		return fmt.Errorf("login as %s: %w", c.Handle, err)
	}
	if out.Did == "" || out.AccessJwt == "" {
		return fmt.Errorf("login as %s: empty session", c.Handle)
	}
	c.did = out.Did
	c.accessJwt = out.AccessJwt
	c.loggedInAt = time.Now()
	return nil
}

// ensureFreshSession re-logs-in if the current session has outlived
// sessionMaxAge. Called before every authenticated request, so a
// long-running bridge process never drifts onto an expired token the way
// it previously did — Login was only ever called once, at startup, and
// nothing afterward refreshed it.
func (c *Client) ensureFreshSession(ctx context.Context) error {
	if c.accessJwt == "" || time.Since(c.loggedInAt) > sessionMaxAge {
		return c.doLogin(ctx)
	}
	return nil
}

// isExpiredToken reports whether err is the PDS's shape for "your access
// token has expired" — {"error":"ExpiredToken",...} — confirmed live
// against pds.cyberwild.org's actual error body, not assumed from docs.
func isExpiredToken(err error) bool {
	return err != nil && strings.Contains(err.Error(), `"error":"ExpiredToken"`)
}

// DID is this bot's own DID, populated after Login.
func (c *Client) DID() string { return c.did }

// serviceAuth mints a short-lived token, signed by our PDS, that
// authorizes exactly one call to lxm on the given service host — the same
// mechanism the Tangled web UI uses (see the package doc comment). aud is
// a did:web derived from the service host.
func (c *Client) serviceAuth(ctx context.Context, serviceHost, lxm string) (string, error) {
	if err := c.ensureFreshSession(ctx); err != nil {
		return "", err
	}
	token, err := c.doServiceAuth(ctx, serviceHost, lxm)
	if isExpiredToken(err) {
		if lerr := c.doLogin(ctx); lerr != nil {
			return "", fmt.Errorf("service auth: re-login after expired token: %w", lerr)
		}
		token, err = c.doServiceAuth(ctx, serviceHost, lxm)
	}
	return token, err
}

func (c *Client) doServiceAuth(ctx context.Context, serviceHost, lxm string) (string, error) {
	aud := "did:web:" + serviceHost
	exp := time.Now().Add(2 * time.Minute).Unix()
	u := fmt.Sprintf("%s/xrpc/com.atproto.server.getServiceAuth?aud=%s&exp=%d&lxm=%s",
		strings.TrimRight(c.PDSBaseURL, "/"), aud, exp, lxm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessJwt)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("getServiceAuth (aud=%s lxm=%s): HTTP %d: %s", aud, lxm, resp.StatusCode, truncate(b, 300))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("getServiceAuth: decode: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("getServiceAuth (aud=%s lxm=%s): empty token", aud, lxm)
	}
	return out.Token, nil
}

// postAuthed is c.post using the current session, refreshed first if
// stale and retried once if the PDS still says it's expired — the single
// chokepoint every accessJwt-bearing write goes through.
func (c *Client) postAuthed(ctx context.Context, baseURL, method string, body []byte, out any) error {
	if err := c.ensureFreshSession(ctx); err != nil {
		return err
	}
	err := c.post(ctx, baseURL, method, c.accessJwt, body, out)
	if isExpiredToken(err) {
		if lerr := c.doLogin(ctx); lerr != nil {
			return fmt.Errorf("%s: re-login after expired token: %w", method, lerr)
		}
		err = c.post(ctx, baseURL, method, c.accessJwt, body, out)
	}
	return err
}

// CreateRepoInput is what CreateRepo needs to create a repo on a knot and
// announce it on our own PDS.
type CreateRepoInput struct {
	Knot          string // hostname only, e.g. "knot.cyberwild.org"
	Rkey          string // record key, also used as the repo name
	Name          string
	DefaultBranch string
	Source        string // git URL to import from, e.g. the Forgejo clone URL
	Description   string
}

// CreateRepoResult is what the caller needs to keep — the repo's own DID
// (required on every issue record) and its AT-URI (for our own bookkeeping
// and for building the repo's Tangled URL).
type CreateRepoResult struct {
	RepoDid string
	AtURI   string
}

// CreateRepo creates a repo on the given knot (which clones Source itself)
// and announces it on our own PDS. Idempotent in practice: Tangled repo
// names are unique per (did, knot), so calling this twice for the same
// Rkey returns a "repo already exists"-shaped error the caller can treat
// as success — see bridge.go's ensureRepo.
func (c *Client) CreateRepo(ctx context.Context, in CreateRepoInput) (CreateRepoResult, error) {
	token, err := c.serviceAuth(ctx, in.Knot, "sh.tangled.repo.create")
	if err != nil {
		return CreateRepoResult{}, fmt.Errorf("service auth for repo.create: %w", err)
	}

	createBody, _ := json.Marshal(map[string]any{
		"rkey":          in.Rkey,
		"name":          in.Name,
		"defaultBranch": in.DefaultBranch,
		"source":        in.Source,
	})
	var createResp struct {
		RepoDid string `json:"repoDid"`
	}
	knotURL := "https://" + in.Knot
	if err := c.post(ctx, knotURL, "sh.tangled.repo.create", token, createBody, &createResp); err != nil {
		return CreateRepoResult{}, fmt.Errorf("knot repo.create: %w", err)
	}
	if createResp.RepoDid == "" {
		return CreateRepoResult{}, fmt.Errorf("knot repo.create: empty repoDid")
	}

	record := map[string]any{
		"$type":     "sh.tangled.repo",
		"name":      in.Name,
		"knot":      in.Knot,
		"createdAt": time.Now().UTC().Format(time.RFC3339),
		"repoDid":   createResp.RepoDid,
	}
	if in.Description != "" {
		record["description"] = in.Description
	}
	if in.Source != "" {
		record["source"] = in.Source
	}
	putBody, _ := json.Marshal(map[string]any{
		"repo":       c.did,
		"collection": "sh.tangled.repo",
		"rkey":       in.Rkey,
		"record":     record,
	})
	var putResp struct {
		URI string `json:"uri"`
	}
	if err := c.postAuthed(ctx, c.PDSBaseURL, "com.atproto.repo.putRecord", putBody, &putResp); err != nil {
		return CreateRepoResult{}, fmt.Errorf("announce repo on PDS: %w", err)
	}

	return CreateRepoResult{RepoDid: createResp.RepoDid, AtURI: putResp.URI}, nil
}

// CreateIssue writes a sh.tangled.repo.issue record on our own PDS.
// repoDid is the target repo's own DID (from CreateRepoResult), not its
// owner's.
func (c *Client) CreateIssue(ctx context.Context, repoDid, title, body string) (atURI string, err error) {
	record := map[string]any{
		"$type":     "sh.tangled.repo.issue",
		"repo":      repoDid,
		"title":     title,
		"body":      body,
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}
	reqBody, _ := json.Marshal(map[string]any{
		"repo":       c.did,
		"collection": "sh.tangled.repo.issue",
		"record":     record,
	})
	var out struct {
		URI string `json:"uri"`
	}
	if err := c.postAuthed(ctx, c.PDSBaseURL, "com.atproto.repo.createRecord", reqBody, &out); err != nil {
		return "", fmt.Errorf("create issue: %w", err)
	}
	return out.URI, nil
}

// CreateComment writes a sh.tangled.repo.issue.comment record replying to
// issueAtURI.
func (c *Client) CreateComment(ctx context.Context, issueAtURI, body string) (atURI string, err error) {
	record := map[string]any{
		"$type":     "sh.tangled.repo.issue.comment",
		"issue":     issueAtURI,
		"body":      body,
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}
	reqBody, _ := json.Marshal(map[string]any{
		"repo":       c.did,
		"collection": "sh.tangled.repo.issue.comment",
		"record":     record,
	})
	var out struct {
		URI string `json:"uri"`
	}
	if err := c.postAuthed(ctx, c.PDSBaseURL, "com.atproto.repo.createRecord", reqBody, &out); err != nil {
		return "", fmt.Errorf("create comment: %w", err)
	}
	return out.URI, nil
}

// post issues one XRPC procedure call and decodes a JSON response. baseURL
// is the service (PDS or knot) to call; bearer is empty for unauthenticated
// calls (none in this package, kept for clarity/future use).
func (c *Client) post(ctx context.Context, baseURL, method, bearer string, body []byte, out any) error {
	u := strings.TrimRight(baseURL, "/") + "/xrpc/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: HTTP %d: %s", method, resp.StatusCode, truncate(b, 300))
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: decode response: %w", method, err)
	}
	return nil
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
