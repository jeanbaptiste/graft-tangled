package bridge

import "testing"

func TestIssueWebURL(t *testing.T) {
	got := issueWebURL("https://tangled.example/", "did:plc:abc", "graft-source", 7)
	if want := "https://tangled.example/did:plc:abc/graft-source/issues/7"; got != want {
		t.Errorf("issueWebURL = %q, want %q", got, want)
	}
}
