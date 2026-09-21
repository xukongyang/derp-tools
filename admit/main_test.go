package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("alice-secret")

func TestAuthHash(t *testing.T) {
	// Deterministic and equal to a hand-computed HMAC-SHA256.
	got := authHash(testSecret, "alice", 12345)
	mac := hmac.New(sha256.New, testSecret)
	mac.Write([]byte("alice:12345"))
	if want := hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Errorf("authHash = %q; want %q", got, want)
	}
	if got == authHash(testSecret, "bob", 12345) {
		t.Error("authHash ignores the username")
	}
	if got == authHash(testSecret, "alice", 12346) {
		t.Error("authHash ignores the window")
	}
}

func TestCheck(t *testing.T) {
	users := map[string]string{"alice": "alice-secret"}
	now := int64(1_700_000_000)
	w := now / windowSecs
	cur := authHash([]byte("alice-secret"), "alice", w)

	if !check(users, "alice", cur, now) {
		t.Error("current-window token rejected; want accepted")
	}
	if !check(users, "alice", authHash([]byte("alice-secret"), "alice", w+1), now) {
		t.Error("next-window token rejected; want accepted (clock skew tolerance)")
	}
	if !check(users, "alice", authHash([]byte("alice-secret"), "alice", w-1), now) {
		t.Error("previous-window token rejected; want accepted (clock skew tolerance)")
	}
	if check(users, "alice", authHash([]byte("alice-secret"), "alice", w-2), now) {
		t.Error("two windows old token accepted; want rejected")
	}
	// Each user's secret only validates their own name.
	if check(users, "alice", authHash([]byte("other-secret"), "alice", w), now) {
		t.Error("token under a different secret accepted; want rejected")
	}
	if check(users, "mallory", authHash([]byte("mallory-secret"), "mallory", w), now) {
		t.Error("unknown user accepted; want rejected")
	}
	if check(users, "alice", strings.ToUpper(cur), now) {
		t.Error("non-hex garbage accepted; want rejected")
	}
}

func TestParseUsers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.txt")
	if err := os.WriteFile(path, []byte("# comment\nalice:alice-secret\n\nbob:bob-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	users, err := readUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users["alice"] != "alice-secret" || users["bob"] != "bob-secret" {
		t.Errorf("readUsers = %v; want alice and bob with their secrets", users)
	}
}

func TestHandleAdmit(t *testing.T) {
	users := map[string]string{"alice": "alice-secret"}
	srv := &server{users: users, logf: func(string, ...any) {}}
	ts := httptest.NewServer(http.HandlerFunc(srv.handleAdmit))
	defer ts.Close()

	w := time.Now().Unix() / windowSecs
	good, _ := json.Marshal(admitRequest{
		NodePublic: "nodekey:abc",
		Source:     "203.0.113.9",
		Username:   "alice",
		AuthHash:   authHash([]byte("alice-secret"), "alice", w),
	})
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader(string(good)))
	if err != nil {
		t.Fatal(err)
	}
	var out admitResponse
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid credentials: status = %d; want 200", resp.StatusCode)
	}
	if !out.Allow {
		t.Error("valid credentials: Allow = false; want true")
	}

	// A user whose secret differs is denied even with a fresh token.
	bad, _ := json.Marshal(admitRequest{
		NodePublic: "nodekey:abc",
		Source:     "203.0.113.9",
		Username:   "mallory",
		AuthHash:   authHash([]byte("mallory-secret"), "mallory", w),
	})
	resp2, err := http.Post(ts.URL, "application/json", strings.NewReader(string(bad)))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("unknown user: status = %d; want 403", resp2.StatusCode)
	}

	// Missing fields are denied, not a parse crash.
	resp3, err := http.Post(ts.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusForbidden {
		t.Errorf("empty request: status = %d; want 403", resp3.StatusCode)
	}

	// Only POST is accepted.
	resp4, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d; want 405", resp4.StatusCode)
	}
}
