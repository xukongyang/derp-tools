package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// newTestDB creates a net2local-shaped sqlite database in a temp
// directory (the users and servers tables admission reads) and
// inserts one users row per entry.
func newTestDB(t *testing.T, rows ...[2]string) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "net2local.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE users (
		name TEXT PRIMARY KEY,
		password TEXT NOT NULL DEFAULT '',
		enable INTEGER NOT NULL DEFAULT 1,
		admin INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE servers (
		name TEXT PRIMARY KEY,
		enable INTEGER NOT NULL DEFAULT 1,
		auth TEXT NOT NULL DEFAULT 'user',
		username TEXT NOT NULL DEFAULT '',
		password TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO users (name, password) VALUES (?, ?)`, r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// addServerRow inserts a servers-table row the way net2local does;
// enable is 1 or 0.
func addServerRow(t *testing.T, db *sql.DB, name, username, password string, enable int) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO servers (name, username, password, enable) VALUES (?, ?, ?, ?)`,
		name, username, password, enable); err != nil {
		t.Fatal(err)
	}
}

func TestLoadUsers(t *testing.T) {
	db := newTestDB(t,
		[2]string{"alice", "s1"},
		[2]string{"bob", "s2"},
	)
	// Disabled and empty-password rows never become admission users.
	if _, err := db.Exec(`INSERT INTO users (name, password, enable) VALUES ('carol', 's3', 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (name, password) VALUES ('dave', '')`); err != nil {
		t.Fatal(err)
	}
	// Server rows join the admission table under their own username.
	addServerRow(t, db, "srv1", "srv1", "sp1", 1)
	// Blank, disabled, and empty-password server rows do not.
	addServerRow(t, db, "srv2", "", "sp2", 1)
	addServerRow(t, db, "srv3", "srv3", "sp3", 0)
	addServerRow(t, db, "srv4", "srv4", "", 1)
	// On a name collision the users row wins.
	addServerRow(t, db, "eve-machine", "eve", "server-secret", 1)
	if _, err := db.Exec(`INSERT INTO users (name, password) VALUES ('eve', 'user-secret')`); err != nil {
		t.Fatal(err)
	}

	users, err := loadUsers(db)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"alice": "s1",
		"bob":   "s2",
		"srv1":  "sp1",
		"eve":   "user-secret",
	}
	if len(users) != len(want) {
		t.Errorf("loadUsers = %v; want %v", users, want)
	}
	for name, secret := range want {
		if users[name] != secret {
			t.Errorf("loadUsers[%q] = %q; want %q (full table: %v)", name, users[name], secret, users)
		}
	}

	// A database without the net2local tables is an error, not an
	// empty table.
	noTablePath := filepath.Join(t.TempDir(), "net2local.db")
	noTable, err := sql.Open("sqlite", noTablePath)
	if err != nil {
		t.Fatal(err)
	}
	defer noTable.Close()
	if _, err = loadUsers(noTable); err == nil {
		t.Error("loadUsers on db without net2local tables = nil error; want error")
	}
}

func TestHandleAdmit(t *testing.T) {
	db := newTestDB(t, [2]string{"alice", "alice-secret"})
	addServerRow(t, db, "1265u-machine", "1265u", "server-secret", 1)
	srv := &server{db: db, logf: func(string, ...any) {}}
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

	// A servers-table row authenticates under its own username.
	srvBody, _ := json.Marshal(admitRequest{
		NodePublic: "nodekey:abc",
		Source:     "203.0.113.9",
		Username:   "1265u",
		AuthHash:   authHash([]byte("server-secret"), "1265u", w),
	})
	resp5, err := http.Post(ts.URL, "application/json", strings.NewReader(string(srvBody)))
	if err != nil {
		t.Fatal(err)
	}
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusOK {
		t.Errorf("valid server credentials: status = %d; want 200", resp5.StatusCode)
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

// TestLiveReload verifies that edits to the users table take effect
// on the next admission check without a restart: rotating a secret,
// disabling a user, and re-enabling them are all picked up live.
func TestLiveReload(t *testing.T) {
	db := newTestDB(t, [2]string{"alice", "s1"})
	srv := &server{db: db}
	ts := httptest.NewServer(http.HandlerFunc(srv.handleAdmit))
	defer ts.Close()
	w := time.Now().Unix() / windowSecs
	try := func(secret string) bool {
		body, _ := json.Marshal(admitRequest{
			NodePublic: "nodekey:abc",
			Source:     "203.0.113.9",
			Username:   "alice",
			AuthHash:   authHash([]byte(secret), "alice", w),
		})
		resp, err := http.Post(ts.URL, "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}

	if !try("s1") {
		t.Fatal("initial table: alice with s1 rejected")
	}

	// Rotate the secret in place: the next check picks it up.
	if _, err := db.Exec(`UPDATE users SET password = 's2' WHERE name = 'alice'`); err != nil {
		t.Fatal(err)
	}
	if try("s1") {
		t.Error("old secret s1 still accepted after rotation")
	}
	if !try("s2") {
		t.Error("new secret s2 rejected after rotation")
	}

	// Disabling the row denies the user immediately.
	if _, err := db.Exec(`UPDATE users SET enable = 0 WHERE name = 'alice'`); err != nil {
		t.Fatal(err)
	}
	if try("s2") {
		t.Error("disabled user accepted")
	}
	// Re-enabling admits them again.
	if _, err := db.Exec(`UPDATE users SET enable = 1 WHERE name = 'alice'`); err != nil {
		t.Fatal(err)
	}
	if !try("s2") {
		t.Error("re-enabled user rejected")
	}

	// Server rows live-reload the same way: a freshly rotated server
	// password takes effect on the next check.
	addServerRow(t, db, "5105-machine", "5105", "old-secret", 1)
	if !tryAs(t, ts, "5105", "old-secret", w) {
		t.Fatal("server row with old-secret rejected")
	}
	if _, err := db.Exec(`UPDATE servers SET password = 'new-secret' WHERE username = '5105'`); err != nil {
		t.Fatal(err)
	}
	if tryAs(t, ts, "5105", "old-secret", w) {
		t.Error("server old-secret still accepted after rotation")
	}
	if !tryAs(t, ts, "5105", "new-secret", w) {
		t.Error("server new-secret rejected after rotation")
	}
}

// tryAs posts an admission request for username with a token computed
// under secret and reports whether it was allowed.
func tryAs(t *testing.T, ts *httptest.Server, username, secret string, w int64) bool {
	t.Helper()
	body, _ := json.Marshal(admitRequest{
		NodePublic: "nodekey:abc",
		Source:     "203.0.113.9",
		Username:   username,
		AuthHash:   authHash([]byte(secret), username, w),
	})
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TestBrokenDbFallback verifies that when the database becomes
// unreadable, the last good table keeps serving instead of taking
// admission down.
func TestBrokenDbFallback(t *testing.T) {
	db := newTestDB(t, [2]string{"alice", "s2"})
	srv := &server{db: db}
	ts := httptest.NewServer(http.HandlerFunc(srv.handleAdmit))
	defer ts.Close()
	w := time.Now().Unix() / windowSecs
	try := func(secret string) bool {
		body, _ := json.Marshal(admitRequest{
			NodePublic: "nodekey:abc",
			Source:     "203.0.113.9",
			Username:   "alice",
			AuthHash:   authHash([]byte(secret), "alice", w),
		})
		resp, err := http.Post(ts.URL, "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}

	if !try("s2") {
		t.Fatal("healthy db: alice with s2 rejected")
	}

	// Close the pool so every query fails; admission stays up on the
	// last loaded table.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Query(`SELECT 1`); err == nil {
		t.Fatal("expected queries against a closed db to fail")
	}
	if !try("s2") {
		t.Error("broken db took the last good table out of service")
	}
	if fmt.Sprint(srv.getUsers()["alice"]) != "s2" {
		t.Error("getUsers lost the last good table after the db broke")
	}
}
