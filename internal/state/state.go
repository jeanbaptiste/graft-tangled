package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// dedupRetention bounds how long a dedup entry survives before pruning —
// same reasoning and window as graft-discourse's state package.
const dedupRetention = 180 * 24 * time.Hour

// KeyPair is the bridge actor's PEM keypair (for signing/verifying
// ActivityPub deliveries to/from Graft).
type KeyPair struct {
	PrivatePEM string `json:"private_pem"`
	PublicPEM  string `json:"public_pem"`
}

// RepoInfo is one series' Tangled repo, created once and reused after.
type RepoInfo struct {
	Knot    string `json:"knot"`
	RepoDid string `json:"repo_did"`
	AtURI   string `json:"at_uri"`
	Rkey    string `json:"rkey"`
}

// State is the bridge's durable bookkeeping, persisted as a JSON file.
type State struct {
	mu   sync.Mutex
	path string

	ActorKeys map[string]KeyPair  `json:"actor_keys"`
	Repos     map[string]RepoInfo `json:"repos"` // series -> Tangled repo

	// IssueByNote maps a Graft note URI to the Tangled issue AT-URI it was
	// mirrored to; IssueToNote is the reverse, for relaying a Tangled
	// comment back to the right Graft note.
	IssueByNote map[string]string `json:"issue_by_note"`
	IssueToNote map[string]string `json:"issue_to_note"`

	// LastCommentID is the highest appview issue_comments.id row already
	// considered, so each pass only reads newly-added rows.
	LastCommentID int64 `json:"last_comment_id"`

	// Delivered and SeenNotes are dedup sets, pruned past dedupRetention —
	// see graft-discourse's state package for why timestamped, not bool.
	Delivered map[string]int64 `json:"delivered"`  // content hash already relayed one direction or the other
	SeenNotes map[string]int64 `json:"seen_notes"` // Graft note URI already mirrored as a Tangled issue
}

// Load reads state from path, creating an empty state if the file is
// absent. A group- or world-accessible file (it holds the actor's private
// key) is refused outright.
func Load(path string) (*State, error) {
	s := &State{path: path}
	if info, err := os.Stat(path); err == nil {
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return nil, fmt.Errorf("state file %s is accessible to other users (mode %04o); run: chmod 600 %s", path, mode, path)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		s.initMaps()
		return s, nil
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	s.initMaps()
	return s, nil
}

func (s *State) initMaps() {
	if s.ActorKeys == nil {
		s.ActorKeys = map[string]KeyPair{}
	}
	if s.Repos == nil {
		s.Repos = map[string]RepoInfo{}
	}
	if s.IssueByNote == nil {
		s.IssueByNote = map[string]string{}
	}
	if s.IssueToNote == nil {
		s.IssueToNote = map[string]string{}
	}
	if s.Delivered == nil {
		s.Delivered = map[string]int64{}
	}
	if s.SeenNotes == nil {
		s.SeenNotes = map[string]int64{}
	}
}

func (s *State) prune() {
	cutoff := time.Now().Add(-dedupRetention).Unix()
	for _, m := range []map[string]int64{s.Delivered, s.SeenNotes} {
		for k, ts := range m {
			if ts < cutoff {
				delete(m, k)
			}
		}
	}
}

// Save atomically writes the state back to disk.
func (s *State) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *State) saveLocked() error {
	s.prune()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.path)
}

func (s *State) KeyPair(name string) (KeyPair, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kp, ok := s.ActorKeys[name]
	return kp, ok
}

func (s *State) SetKeyPair(name string, kp KeyPair) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ActorKeys[name] = kp
	return s.saveLocked()
}

// Repo returns the Tangled repo created for a series, if any.
func (s *State) Repo(series string) (RepoInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.Repos[series]
	return r, ok
}

// SetRepo records a series' Tangled repo and persists.
func (s *State) SetRepo(series string, r RepoInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Repos[series] = r
	return s.saveLocked()
}

// IssueForNote returns the Tangled issue AT-URI mirrored from a Graft note.
func (s *State) IssueForNote(noteURI string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.IssueByNote[noteURI]
	return v, ok
}

// NoteForIssue returns the Graft note URI a Tangled issue was mirrored
// from, so a new comment on it can be relayed back to the right place.
func (s *State) NoteForIssue(issueAtURI string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.IssueToNote[issueAtURI]
	return v, ok
}

// LinkIssue records a Graft note <-> Tangled issue pairing and persists.
func (s *State) LinkIssue(noteURI, issueAtURI string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.IssueByNote[noteURI] = issueAtURI
	s.IssueToNote[issueAtURI] = noteURI
	return s.saveLocked()
}

// WatchedIssues returns every Tangled issue AT-URI this bridge created and
// is watching for new comments.
func (s *State) WatchedIssues() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.IssueToNote))
	for uri := range s.IssueToNote {
		out = append(out, uri)
	}
	return out
}

func (s *State) SeenNote(noteURI string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.SeenNotes[noteURI]
	return ok
}

func (s *State) MarkSeenNote(noteURI string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SeenNotes[noteURI] = time.Now().Unix()
	return s.saveLocked()
}

func (s *State) IsDelivered(hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.Delivered[hash]
	return ok
}

func (s *State) MarkDelivered(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Delivered[hash] = time.Now().Unix()
	return s.saveLocked()
}

// CommentCursor returns the highest appview issue_comments.id row already
// considered.
func (s *State) CommentCursor() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.LastCommentID
}

// SetCommentCursor advances the cursor and persists. A no-op if id doesn't
// move it forward.
func (s *State) SetCommentCursor(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id <= s.LastCommentID {
		return nil
	}
	s.LastCommentID = id
	return s.saveLocked()
}
