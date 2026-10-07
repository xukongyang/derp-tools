// The admit-sqlite command runs the admission controller for a
// private derper: it answers the POST requests derper sends to the
// URL configured with --verify-client-url, checking a username and a
// time-limited token against a per-user secret list — the same
// protocol as the admit command, but reading users from a net2local
// sqlite database instead of a users file. Two tables feed the
// admission list: the users table's enabled rows (people) and the
// servers table's enabled rows (the managed machines, under their
// own username:password), merged into one table.
//
// The token is HMAC-SHA256(secret, username + ":" + window) in hex,
// where window is unix time divided by 5 minutes and secret is that
// user's password column. Tokens from the current, previous, and next
// window are accepted, so client clocks may drift by up to five
// minutes. The token travels inside the DERP client's ClientInfo
// (sealed to the server's key) and then in the admission request body
// (over HTTPS), never in the clear. tailcat computes the same token
// internally when given --derp-auth-secret.
//
// Both tables are queried on every admission check, so rows the
// net2local server inserts, deletes, or disables (enable = 0) take
// effect on the next check without a restart. The database is opened
// read-only: admit-sqlite never writes to net2local's data. If the
// database cannot be read, the last successfully loaded table keeps
// serving and the problem is only logged: a broken database should
// not take admission down.
//
// Usage:
//
//	admit-sqlite -db net2local.db [-listen :8080]
//	admit-sqlite -gen -user alice -db net2local.db
//
// The first form runs the server. The second prints the current
// token for a user, for pasting into tailcat's --derp-auth-token.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// windowSecs is the token validity period. Tokens from the current
// window and its immediate neighbors are accepted.
const windowSecs int64 = 300

// admitRequest mirrors the JSON body derper POSTs to
// --verify-client-url: the client's public key and address, plus the
// admission credentials from its ClientInfo (our patched tailcat).
type admitRequest struct {
	NodePublic string `json:"NodePublic"`
	Source     string `json:"Source"`
	Username   string `json:"Username"`
	AuthHash   string `json:"AuthHash"`
}

// admitResponse mirrors the JSON body derper expects back.
type admitResponse struct {
	Allow bool `json:"Allow"`
}

func main() {
	listen := flag.String("listen", ":8080", "listen address for the admission HTTP server")
	dbPath := flag.String("db", "", "path to the net2local sqlite database whose users table holds username:secret")
	gen := flag.Bool("gen", false, "print the current token for -user instead of running the server")
	user := flag.String("user", "", "with -gen, the username to compute a token for")
	flag.Parse()

	if *dbPath == "" {
		log.Fatal("no -db given")
	}
	db, err := sql.Open("sqlite", "file:"+*dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatalf("opening %v: %v", *dbPath, err)
	}
	defer db.Close()

	users, err := loadUsers(db)
	if err != nil {
		log.Fatalf("reading users: %v", err)
	}
	if len(users) == 0 {
		log.Fatalf("no enabled users in %v", *dbPath)
	}

	if *gen {
		secret, ok := users[*user]
		if !ok {
			log.Fatalf("user %q is not enabled in %v", *user, *dbPath)
		}
		fmt.Println(authHash([]byte(secret), *user, time.Now().Unix()/windowSecs))
		return
	}

	srv := &server{db: db, users: users, logf: log.Printf}
	log.Printf("admit-sqlite: loaded %d user(s) from %v; users-table edits take effect without a restart", len(users), *dbPath)
	log.Printf("admit-sqlite: serving on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, http.HandlerFunc(srv.handleAdmit)))
}

// authHash returns the hex HMAC-SHA256 of "username:window" under
// secret. tailcat's --derp-auth-secret mode computes the same value
// client-side.
func authHash(secret []byte, username string, window int64) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%s:%d", username, window)
	return hex.EncodeToString(mac.Sum(nil))
}

// check reports whether username's token is valid: the user must be
// listed, and the token must match the HMAC computed under that
// user's own secret for the current, next, or previous window
// (tolerating modest clock drift). The comparison is constant-time.
func check(users map[string]string, username, token string, now int64) bool {
	secret, ok := users[username]
	if !ok {
		return false
	}
	window := now / windowSecs
	for _, d := range []int64{-1, 0, 1} {
		want := authHash([]byte(secret), username, window+d)
		if hmac.Equal([]byte(want), []byte(token)) {
			return true
		}
	}
	return false
}

// server is the admission controller's HTTP state. The users and
// servers tables are re-queried on every admission check, so changes
// made by the net2local server take effect immediately; on a database
// error the last successfully loaded table keeps serving.
type server struct {
	db    *sql.DB
	mu    sync.Mutex
	users map[string]string // last successfully loaded table
	logf  func(format string, args ...any)
}

// getUsers returns the current user table, re-reading the database
// on each call. If the database is missing, unreadable, or
// malformed, the last good table keeps serving and the problem is
// only logged.
func (s *server) getUsers() map[string]string {
	users, err := loadUsers(s.db)
	if err != nil {
		if s.logf != nil {
			s.logf("admit-sqlite: reading users: %v; serving the last loaded table", err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.users
	}
	s.mu.Lock()
	if s.logf != nil && len(users) != len(s.users) {
		s.logf("admit-sqlite: users reloaded: %d user(s)", len(users))
	}
	s.users = users
	s.mu.Unlock()
	return users
}

// handleAdmit implements the derper admission protocol: POST with
// NodePublic, Source, Username, and AuthHash; 200 with Allow:true
// admits the client, anything else denies it.
func (s *server) handleAdmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req admitRequest
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	allowed := check(s.getUsers(), req.Username, req.AuthHash, time.Now().Unix())
	if s.logf != nil {
		s.logf("admit-sqlite: user=%q key=%v source=%v -> %v", req.Username, req.NodePublic, req.Source, allowed)
	}
	w.Header().Set("Content-Type", "application/json")
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(admitResponse{Allow: false})
		return
	}
	json.NewEncoder(w).Encode(admitResponse{Allow: true})
}

// loadUsers reads the admission table from the net2local database,
// merging two sources into one username:secret map: the users
// table's enabled rows (people) and the servers table's enabled rows
// (the managed machines, whose username:password pairs are their own
// admission credentials). On a name collision a users-table row
// wins. Rows with an empty name or password are skipped, mirroring
// the users file's refusal of empty secrets: an empty secret would
// let anyone holding just the username forge that user's tokens.
func loadUsers(db *sql.DB) (map[string]string, error) {
	users := make(map[string]string)
	if err := addUsers(db, users, `SELECT name, password FROM users WHERE enable = 1`); err != nil {
		return nil, err
	}
	// Servers second: an equally-named users row keeps its own secret.
	if err := addUsers(db, users, `SELECT username, password FROM servers WHERE enable = 1`); err != nil {
		return nil, err
	}
	return users, nil
}

// addUsers runs query and merges its (name, password) rows into
// users, skipping blank names and secrets and leaving rows already
// present untouched.
func addUsers(db *sql.DB, users map[string]string, query string) error {
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, secret string
		if err := rows.Scan(&name, &secret); err != nil {
			return err
		}
		if name == "" || secret == "" {
			continue
		}
		if _, ok := users[name]; !ok {
			users[name] = secret
		}
	}
	return rows.Err()
}
