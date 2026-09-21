// The admit command runs the admission controller for a private
// derper: it answers the POST requests derper sends to the URL
// configured with --verify-client-url, checking a username and a
// time-limited token against a per-user secret list.
//
// The token is HMAC-SHA256(secret, username + ":" + window) in hex,
// where window is unix time divided by 5 minutes and secret is that
// user's own secret from the users file. Tokens from the current,
// previous, and next window are accepted, so client clocks may drift
// by up to five minutes. The token travels inside the DERP client's
// ClientInfo (sealed to the server's key) and then in the admission
// request body (over HTTPS), never in the clear. tailcat computes
// the same token internally when given --derp-auth-secret.
//
// The users file lists one user per line as "username:secret"
// (# comments and blank lines are ignored). Each user's secret is
// independent; leaking one does not enable forging another's tokens.
//
// Usage:
//
//	admit -users-file users.txt [-listen :8080]
//	admit -gen -user alice -users-file users.txt
//
// The first form runs the server. The second prints the current
// token for a user, for pasting into tailcat's --derp-auth-token.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
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
	usersFile := flag.String("users-file", "", `file with one user per line as "username:secret"`)
	gen := flag.Bool("gen", false, "print the current token for -user instead of running the server")
	user := flag.String("user", "", "with -gen, the username to compute a token for")
	flag.Parse()

	users, err := readUsers(*usersFile)
	if err != nil {
		log.Fatalf("reading users: %v", err)
	}
	if len(users) == 0 {
		log.Fatal("no users listed")
	}

	if *gen {
		secret, ok := users[*user]
		if !ok {
			log.Fatalf("user %q is not in %v", *user, *usersFile)
		}
		fmt.Println(authHash([]byte(secret), *user, time.Now().Unix()/windowSecs))
		return
	}

	srv := &server{users: users, logf: log.Printf}
	log.Printf("admit: serving %d user(s) on %s", len(users), *listen)
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

// server is the admission controller's HTTP state.
type server struct {
	users map[string]string
	logf  func(format string, args ...any)
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
	allowed := check(s.users, req.Username, req.AuthHash, time.Now().Unix())
	if s.logf != nil {
		s.logf("admit: user=%q key=%v source=%v -> %v", req.Username, req.NodePublic, req.Source, allowed)
	}
	w.Header().Set("Content-Type", "application/json")
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(admitResponse{Allow: false})
		return
	}
	json.NewEncoder(w).Encode(admitResponse{Allow: true})
}

// readUsers parses the users file: one "username:secret" per line;
// blank lines and # comments are ignored. The first colon separates
// the name from the secret, so secrets must not contain colons.
func readUsers(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	users := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, secret, ok := strings.Cut(line, ":")
		if !ok || name == "" || secret == "" {
			return nil, fmt.Errorf("%v: line %q is not username:secret", path, line)
		}
		users[name] = secret
	}
	return users, nil
}
