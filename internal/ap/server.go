package ap

import (
	"encoding/json"
	"net/http"
)

// ActorServer serves the bridge's own actor document so Graft can resolve
// our public key and verify the signatures on replies we deliver. It is
// deliberately read-only: the bridge polls Graft's public outbox rather
// than following and receiving inbox deliveries, so no inbox is exposed.
type ActorServer struct {
	// BaseURL is the bridge's public origin, e.g. "https://bridge.example.org".
	BaseURL string
	// Name is the actor's preferred username, e.g. "discourse".
	Name string
	// PublicPEM is the actor's PKIX PEM public key.
	PublicPEM string
	// RepoURL is an optional profile link shown to remote servers.
	RepoURL string
}

// ActorURL returns the actor's canonical id.
func (s *ActorServer) ActorURL() string { return s.BaseURL + "/actors/" + s.Name }

// KeyID returns the publicKey id Graft expects on our Signature header.
func (s *ActorServer) KeyID() string { return s.ActorURL() + "#main-key" }

// Actor builds the actor document served at ActorURL.
func (s *ActorServer) Actor() Actor {
	base := s.ActorURL()
	return Actor{
		Context:           []string{"https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"},
		ID:                base,
		Type:              "Service",
		PreferredUsername: s.Name,
		Name:              s.Name,
		Summary:           "Tangled <-> Graft bridge",
		URL:               s.RepoURL,
		Inbox:             base + "/inbox",
		Outbox:            base + "/outbox",
		Followers:         base + "/followers",
		PublicKey: PublicKey{
			ID:           s.KeyID(),
			Owner:        base,
			PublicKeyPem: s.PublicPEM,
		},
	}
}

// Handler serves the WebFinger endpoint and the actor document. Mount it on
// the bridge's public HTTP server.
func (s *ActorServer) Handler() http.Handler {
	mux := http.NewServeMux()
	s.Register(mux)
	return mux
}

// Register mounts the WebFinger and actor routes on mux, so the actor
// surface and other routes (e.g. the admin API) can share one server.
func (s *ActorServer) Register(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/webfinger", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		res := r.URL.Query().Get("resource")
		want := "acct:" + s.Name + "@" + hostOf(s.BaseURL)
		if res != "" && res != want {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, "application/jrd+json", map[string]any{
			"subject": want,
			"links": []map[string]string{
				{"rel": "self", "type": ContentType, "href": s.ActorURL()},
			},
		})
	})
	mux.HandleFunc("/actors/"+s.Name, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, ContentType, s.Actor())
	})
}

func writeJSON(w http.ResponseWriter, contentType string, v any) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// hostOf strips the scheme from a base URL. Kept dependency-free rather
// than pulling net/url into a hot path.
func hostOf(base string) string {
	s := base
	if i := indexOf(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := indexOf(s, "/"); i >= 0 {
		s = s[:i]
	}
	return s
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
