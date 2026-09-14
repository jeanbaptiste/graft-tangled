package netguard

import "testing"

func TestValidateRejectsSSRFTargets(t *testing.T) {
	o := Options{}
	bad := []string{
		"http://example.com/x",            // http not allowed
		"https://localhost/x",             // loopback name
		"https://127.0.0.1/x",             // loopback ip
		"https://10.0.0.5/x",              // private
		"https://169.254.169.254/latest",  // link-local metadata
		"https://[::1]/x",                 // ipv6 loopback
		"https://[fd00::1]/x",             // ipv6 unique local
		"https://user:pass@example.com/x", // userinfo
		"https://box.local/x",             // .local
		"https://100.64.0.1/x",            // CGNAT
		"ftp://example.com/x",             // wrong scheme
	}
	for _, u := range bad {
		if err := o.Validate(u); err == nil {
			t.Errorf("Validate(%q) = nil, want error", u)
		}
	}
}

func TestValidateAcceptsPublicHTTPS(t *testing.T) {
	o := Options{}
	for _, u := range []string{"https://f1.cyberwild.org/actors/x", "https://1.1.1.1/x"} {
		if err := o.Validate(u); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", u, err)
		}
	}
}

func TestAllowPrivateAndHTTPOptIn(t *testing.T) {
	o := Options{AllowPrivate: true, AllowHTTP: true}
	if err := o.Validate("http://192.168.1.10:3000/x"); err != nil {
		t.Errorf("opted-in private http rejected: %v", err)
	}
}
