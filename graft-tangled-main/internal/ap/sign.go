package ap

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ContentType is the ActivityStreams media type Graft serves and expects.
const ContentType = "application/activity+json"

// MaxBody caps how much of a remote response we read into memory.
const MaxBody = 1 << 20

// maxClockSkew mirrors Graft's inbound replay window.
const maxClockSkew = 5 * time.Minute

// signedHeaders is the fixed header set we sign. Kept identical to Graft's
// so both sides accept each other's requests.
var signedHeaders = []string{"(request-target)", "host", "date", "digest"}

// requiredSignedHeaders is the minimum a verified inbound signature must
// actually cover. The signer declares which headers it signed via the
// Signature header's own "headers" parameter — attacker-controlled input
// on an inbound request — so VerifyRequest must not trust a short list.
// Without this, a request validly signed over a minimal set (say, just
// "date") could be replayed against a different method or path: the
// Digest check still binds the body, but nothing would bind the
// request-target itself. Requiring both here closes that gap regardless
// of what the sender claims to have signed.
var requiredSignedHeaders = []string{"(request-target)", "digest"}

// SignRequest signs req per draft-cavage HTTP Signatures: (request-target),
// host, date and a SHA-256 Digest of body. Sets Digest, Date and Signature.
func SignRequest(req *http.Request, body []byte, keyID string, priv *rsa.PrivateKey) error {
	digest := sha256.Sum256(body)
	req.Header.Set("Digest", "SHA-256="+base64.StdEncoding.EncodeToString(digest[:]))
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	signingString := buildSigningString(signedHeaders, req.Method, req.URL.RequestURI(), host, req.Header)
	hashed := sha256.Sum256([]byte(signingString))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return fmt.Errorf("sign request: %w", err)
	}
	req.Header.Set("Signature", fmt.Sprintf(
		`keyId="%s",algorithm="rsa-sha256",headers="%s",signature="%s"`,
		keyID, strings.Join(signedHeaders, " "), base64.StdEncoding.EncodeToString(sig),
	))
	return nil
}

// VerifyRequest verifies an inbound request's Signature against pub,
// re-deriving the signing string from the header set the signature claims.
// It requires a Date (replay window), a Digest (body binding) and, when the
// sender declares one, the rsa-sha256 algorithm.
func VerifyRequest(r *http.Request, body []byte, pub *rsa.PublicKey) error {
	params := parseSignatureHeader(r.Header.Get("Signature"))
	if params["signature"] == "" {
		return fmt.Errorf("missing or unparseable Signature header")
	}
	if params["keyId"] == "" {
		return fmt.Errorf("missing keyId in Signature header")
	}
	if alg := params["algorithm"]; alg != "" && !strings.EqualFold(alg, "rsa-sha256") {
		return fmt.Errorf("unsupported signature algorithm %q", alg)
	}

	dateHeader := r.Header.Get("Date")
	if dateHeader == "" {
		return fmt.Errorf("missing Date header")
	}
	signedAt, err := http.ParseTime(dateHeader)
	if err != nil {
		return fmt.Errorf("unparseable Date header: %w", err)
	}
	if skew := time.Since(signedAt); skew > maxClockSkew || skew < -maxClockSkew {
		return fmt.Errorf("Date header too far from current time (skew %s), possible replay", skew)
	}

	digestHeader := r.Header.Get("Digest")
	if digestHeader == "" {
		return fmt.Errorf("missing Digest header")
	}
	sum := sha256.Sum256(body)
	want := "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
	if !strings.EqualFold(digestHeader, want) {
		return fmt.Errorf("digest does not match body")
	}

	headers := strings.Fields(params["headers"])
	if len(headers) == 0 {
		headers = []string{"date"}
	}
	for _, req := range requiredSignedHeaders {
		if !containsFold(headers, req) {
			return fmt.Errorf("signature does not cover required header %q (covers: %s)", req, strings.Join(headers, " "))
		}
	}
	host := r.Header.Get("Host")
	if host == "" {
		host = r.Host
	}
	signingString := buildSigningString(headers, r.Method, r.URL.RequestURI(), host, r.Header)

	sigBytes, err := base64.StdEncoding.DecodeString(params["signature"])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	hashed := sha256.Sum256([]byte(signingString))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sigBytes); err != nil {
		return fmt.Errorf("signature does not verify: %w", err)
	}
	return nil
}

// PostSigned sends a signed POST of an activity+json body, authenticated
// as keyID using priv.
func PostSigned(client *http.Client, url, keyID string, priv *rsa.PrivateKey, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", ContentType)
	if err := SignRequest(req, body, keyID, priv); err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
		return fmt.Errorf("post %s: HTTP %d: %s", url, resp.StatusCode, truncateForLog(b))
	}
	return nil
}

func buildSigningString(headers []string, method, requestURI, host string, reqHeaders http.Header) string {
	lines := make([]string, 0, len(headers))
	for _, h := range headers {
		switch strings.ToLower(h) {
		case "(request-target)":
			lines = append(lines, fmt.Sprintf("(request-target): %s %s", strings.ToLower(method), requestURI))
		case "host":
			lines = append(lines, "host: "+host)
		default:
			lines = append(lines, strings.ToLower(h)+": "+reqHeaders.Get(h))
		}
	}
	return strings.Join(lines, "\n")
}

func parseSignatureHeader(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[kv[0]] = strings.Trim(kv[1], `"`)
	}
	return out
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func truncateForLog(b []byte) string {
	const max = 500
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "... (truncated)"
}
