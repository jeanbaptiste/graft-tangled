package ap

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testKeys(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	privPEM, pubPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return privPEM, pubPEM
}

func TestSignVerifyRoundTrip(t *testing.T) {
	privPEM, pubPEM := testKeys(t)
	priv, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	pub, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}

	body := []byte(`{"type":"Create","actor":"https://b.example/actors/bridge"}`)
	req := httptest.NewRequest(http.MethodPost, "https://g.example/actors/series/inbox", bytes.NewReader(body))
	if err := SignRequest(req, body, "https://b.example/actors/bridge#main-key", priv); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if err := VerifyRequest(req, body, pub); err != nil {
		t.Fatalf("VerifyRequest on freshly signed request: %v", err)
	}

	if err := VerifyRequest(req, []byte("tampered"), pub); err == nil {
		t.Fatal("VerifyRequest accepted a tampered body")
	}
}

func TestVerifyRejectsStaleDate(t *testing.T) {
	privPEM, pubPEM := testKeys(t)
	priv, _ := ParsePrivateKey(privPEM)
	pub, _ := ParsePublicKey(pubPEM)

	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "https://g.example/actors/series/inbox", bytes.NewReader(body))
	if err := SignRequest(req, body, "k", priv); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	req.Header.Set("Date", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	if err := VerifyRequest(req, body, pub); err == nil {
		t.Fatal("VerifyRequest accepted a stale Date header")
	}
}

// TestVerifyRejectsUnderSignedHeaders checks that VerifyRequest refuses a
// signature that validly covers only a minimal header set (here, just
// "date") — the sender's own "headers" parameter is attacker-controlled
// input on an inbound request, and a signature that doesn't bind
// (request-target) would let a captured request be replayed against a
// different method or path.
func TestVerifyRejectsUnderSignedHeaders(t *testing.T) {
	privPEM, pubPEM := testKeys(t)
	priv, _ := ParsePrivateKey(privPEM)
	pub, _ := ParsePublicKey(pubPEM)

	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "https://g.example/actors/series/inbox", bytes.NewReader(body))
	sum := sha256.Sum256(body)
	req.Header.Set("Digest", "SHA-256="+base64.StdEncoding.EncodeToString(sum[:]))
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	// Sign over "date" only, the way SignRequest never does but a hostile
	// or buggy peer's Signature header could claim to. The Digest header
	// above still matches the real body, so this isolates the missing
	// (request-target) coverage as the only thing VerifyRequest can catch.
	hashed := sha256.Sum256([]byte("date: " + req.Header.Get("Date")))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req.Header.Set("Signature", `keyId="k",algorithm="rsa-sha256",headers="date",signature="`+base64.StdEncoding.EncodeToString(sig)+`"`)

	if err := VerifyRequest(req, body, pub); err == nil {
		t.Fatal("VerifyRequest accepted a signature that doesn't cover (request-target)/digest")
	}
}

func TestParseNoteURIRoundTrip(t *testing.T) {
	uri := NoteURI("g.example", "federation-x", 42)
	series, id, ok := ParseNoteURI("g.example", uri)
	if !ok || series != "federation-x" || id != 42 {
		t.Fatalf("ParseNoteURI(%q) = %q,%d,%v", uri, series, id, ok)
	}
	if _, _, ok := ParseNoteURI("g.example", "https://evil.example/actors/x/notes/1"); ok {
		t.Fatal("ParseNoteURI accepted a foreign host")
	}
}
