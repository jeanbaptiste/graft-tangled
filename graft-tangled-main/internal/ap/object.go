package ap

import (
	"strconv"
	"strings"
)

// Actor is the ActivityPub actor for the bridge. Graft's actor type is
// "Service"; we match that so the publicKey is resolved the same way.
type Actor struct {
	Context           []string  `json:"@context"`
	ID                string    `json:"id"`
	Type              string    `json:"type"`
	PreferredUsername string    `json:"preferredUsername"`
	Name              string    `json:"name"`
	Summary           string    `json:"summary,omitempty"`
	URL               string    `json:"url,omitempty"`
	Inbox             string    `json:"inbox"`
	Outbox            string    `json:"outbox"`
	Followers         string    `json:"followers"`
	PublicKey         PublicKey `json:"publicKey"`
}

type PublicKey struct {
	ID           string `json:"id"`
	Owner        string `json:"owner"`
	PublicKeyPem string `json:"publicKeyPem"`
}

// Note is a minimal ActivityStreams Note. Outbound replies set InReplyTo to
// the Graft issue/patch note URI; Graft's inbox reads exactly these fields.
type Note struct {
	Context      string   `json:"@context,omitempty"`
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	AttributedTo string   `json:"attributedTo"`
	InReplyTo    string   `json:"inReplyTo,omitempty"`
	Content      string   `json:"content"`
	URL          string   `json:"url,omitempty"`
	Published    string   `json:"published"`
	To           []string `json:"to,omitempty"`
}

// Create is a Create activity wrapping a Note.
type Create struct {
	Context   string   `json:"@context,omitempty"`
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Actor     string   `json:"actor"`
	Published string   `json:"published,omitempty"`
	To        []string `json:"to,omitempty"`
	Object    Note     `json:"object"`
}

// Follow is a Follow activity sent to a Graft series to subscribe to it.
type Follow struct {
	Context string `json:"@context"`
	ID      string `json:"id"`
	Type    string `json:"type"`
	Actor   string `json:"actor"`
	Object  string `json:"object"`
}

// OrderedCollection is the subset of a Graft outbox we decode.
type OrderedCollection struct {
	Context      string   `json:"@context"`
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	TotalItems   int      `json:"totalItems"`
	OrderedItems []Create `json:"orderedItems"`
}

// PublicAudience is the ActivityStreams public collection IRI.
const PublicAudience = "https://www.w3.org/ns/activitystreams#Public"

// ActorURI returns the canonical actor URI for a name on host.
func ActorURI(host, name string) string {
	return "https://" + host + "/actors/" + name
}

// NoteURI returns the stable object URI for one Graft activity_log entry's
// Note. This is the value a reply's inReplyTo must carry for Graft to route
// the reply as a comment on the underlying issue/patch.
func NoteURI(host, series string, entryID int64) string {
	return ActorURI(host, series) + "/notes/" + strconv.FormatInt(entryID, 10)
}

// ParseNoteURI is NoteURI's inverse: given an inReplyTo URI, extract the
// series and activity_log id it names. Returns ok=false for anything not
// addressed to host under /actors/{series}/notes/{id}.
func ParseNoteURI(host, uri string) (series string, entryID int64, ok bool) {
	prefix := "https://" + host + "/actors/"
	rest := strings.TrimPrefix(uri, prefix)
	if rest == uri {
		return "", 0, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[1] != "notes" {
		return "", 0, false
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return parts[0], id, true
}
