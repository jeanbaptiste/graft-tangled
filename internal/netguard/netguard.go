// Package netguard builds HTTP clients that resist SSRF and credential
// leakage. Dialogue with *configured* services (our Discourse, our Graft)
// is trusted; anything a remote host supplies (an actor's inbox URL, an
// HTTP redirect target) is not, and is validated before we dial it.
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options configures a hardened client.
type Options struct {
	// AllowPrivate permits dialing private/loopback addresses. Set true for
	// a self-hosted Discourse on an internal network; keep false for
	// anything reachable from a remote-provided URL (Graft actor inboxes).
	AllowPrivate bool
	// AllowHTTP permits plaintext http:// URLs. Kept false in production so
	// API keys and signed bodies never travel in the clear.
	AllowHTTP bool
	// SensitiveHeaders are stripped from redirects to a different host, so
	// an Api-Key never leaks to a redirect target.
	SensitiveHeaders []string
	// MaxRedirects bounds redirect chains (default 3).
	MaxRedirects int
	// Timeout is the whole-request timeout (default 20s).
	Timeout time.Duration
}

// Validate checks a URL that may have been supplied by a remote peer.
func (o Options) Validate(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "https" && !(o.AllowHTTP && u.Scheme == "http") {
		return fmt.Errorf("scheme %q not allowed", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("userinfo is not allowed in URLs")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".local") {
		return fmt.Errorf("host %q is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil && !ipAllowed(ip, o.AllowPrivate) {
		return fmt.Errorf("address %s is not allowed", host)
	}
	return nil
}

// Client returns a hardened *http.Client.
func (o Options) Client() *http.Client {
	if o.MaxRedirects == 0 {
		o.MaxRedirects = 3
	}
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return o.dial(ctx, dialer, network, addr)
		},
	}
	return &http.Client{
		Timeout:   o.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= o.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", o.MaxRedirects)
			}
			if err := o.Validate(req.URL.String()); err != nil {
				return fmt.Errorf("refusing redirect: %w", err)
			}
			if len(via) > 0 && !sameHost(via[0].URL, req.URL) {
				for _, h := range o.SensitiveHeaders {
					req.Header.Del(h)
				}
			}
			return nil
		},
	}
}

// dial resolves the host and, unless private addresses are allowed, dials a
// validated public IP directly — defeating DNS rebinding, where a name
// resolves to a public address for validation and a private one at dial
// time.
func (o Options) dial(ctx context.Context, dialer *net.Dialer, network, addr string) (net.Conn, error) {
	if o.AllowPrivate {
		return dialer.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ipAllowed(ip, false) {
			return nil, fmt.Errorf("refusing to dial non-public address %s", host)
		}
		return dialer.DialContext(ctx, network, addr)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, ia := range ips {
		if !ipAllowed(ia.IP, false) {
			continue
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ia.IP.String(), port))
	}
	return nil, fmt.Errorf("no public address for %s", host)
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname())
}

// ipAllowed reports whether ip is safe to dial. Private ranges, loopback,
// link-local, CGNAT and other special-purpose blocks are rejected unless
// allowPrivate is set.
func ipAllowed(ip net.IP, allowPrivate bool) bool {
	if allowPrivate {
		return true
	}
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, n := range blocked {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

var blocked = mustCIDRs(
	"0.0.0.0/8",
	"100.64.0.0/10", // CGNAT
	"192.0.0.0/24",
	"192.0.2.0/24", // TEST-NET-1
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"fc00::/7",  // unique local
	"fe80::/10", // link-local
	"2001:db8::/32",
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}
