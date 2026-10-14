# derp-tools: design and implementation

This workspace builds and operates the private-DERP side of the
tailcat deployment: a patched derper, the admission controllers it
calls, and the end-to-end testbed. The tailcat client side (map
sources, key sources, credential flags) is documented in
`docs/private-derp.md` in the tailcat fork's `dev` branch.

## 1. Layout

```
build.sh          rebuild ./derper from patches/ on a pinned base
patches/          the four derper commits — the single source of truth
admit/            admission controller, users from a users.txt file
admit-sqlite/     admission controller, users from net2local.db
tailscale/        nested clone of tailscale (gitignored); a scratch
                  area, never edited by hand
testdata/         e2e derpmap + self-signed cert (CN/SAN "local")
users.txt         production user:secret list (gitignored)
net2local.db      live credential database (gitignored, read-only use)
derper            built binary (gitignored)
admit-server[-sqlite]  built binaries (gitignored)
```

## 2. The derper patches

`patches/000{1..4}-*.patch` are `git format-patch` exports of the
`auth-patch` branch of the tailscale fork
(github.com/xukongyang/tailscale). They are the single source of
truth: the branch is a convenience for `go.mod` replaces, and
`build.sh` never depends on it.

1. **derp, derphttp: carry optional admission credentials in
   ClientInfo** — adds `AuthUsername`/`AuthToken` to the DERP
   `ClientInfo` and the `derphttp.Client` fields that feed them.
   ClientInfo is sealed to the server's node key on the wire, so
   the credentials are confidential and their integrity is bound
   to the sender's key.
2. **wgengine/magicsock: add Conn.SetDERPAuth** — the engine-level
   entry point that stores credentials for regions not yet dialed
   (and, since patch 4, for dialed ones too).
3. **derp/derpserver: forward ClientInfo admission credentials to
   the admission controller** — on accept, the derper POSTs
   `{NodePublic, Source, Username, AuthHash}` to
   `-verify-client-url` and rejects the connection unless the
   controller answers `{"Allow":true}`. A 403 answer always
   rejects; an unreachable controller rejects only when
   `-verify-client-url-fail-open=false` (the default is fail-open:
   availability over strictness).
4. **derphttp, magicsock: push rotated admission credentials to
   live clients** — `derphttp.Client.SetAuth` (leaf-mutex guard)
   plus `SetDERPAuth` walking `activeDerp`. Before this patch a
   client snapshotted its token at process start and, after a
   derper restart, reconnected forever with the expired token;
   now the rotation timer's next tick re-arms every connection and
   reconnections present a token at most one refresh interval old.

The patches touch five files (`derp/derp_client.go`,
`derp/derphttp/derphttp_client.go`, `derp/derpserver/derpserver.go`,
`wgengine/magicsock/derp.go`, `wgengine/magicsock/magicsock.go`) and
are kept small deliberately: upstream churn in these files is the
only rebase friction.

## 3. build.sh

Idempotent: hard-detach the nested clone to `TAILSCALE_COMMIT`
(pinned to the base the current patches were rebased onto; kept in
sync with tailcat's `go.mod` replace), `git apply patches/*.patch`,
`go build ./cmd/derper`. The `auth-patch` branch pointer is never
moved by builds. Rebuilding after a rebase: export fresh patches
with `git format-patch origin/main..auth-patch -o …`, copy them
over `patches/`, update `TAILSCALE_COMMIT`, run `./build.sh`.

## 4. Admission controllers

Both controllers implement the same protocol: POST with
`{NodePublic, Source, Username, AuthHash}`; `200 {"Allow":true}`
admits, `403 {"Allow":false}` (or any other outcome) denies. POST
only; other methods get 405. Requests are logged per check with the
verdict — the log is the audit trail.

Token check (identical on both sides and in tailcat): the user must
be known, and the token must equal
`hex(HMAC-SHA256(secret, username ":" window))` for the current,
previous, or next 300-second window, compared in constant time.
Per-user secrets; blank secrets or names are never admitted (an
empty secret would let anyone forge that user's tokens with just
the username).

### admit (users.txt)

One `username:secret` per line, `#` comments. The file is re-read
whenever its mtime changes (checked before each admission request),
so edits take effect without a restart; a missing, unreadable, or
malformed file keeps the last good table serving, with a warning —
a broken edit must not take admission down. `-gen -user X` prints
the current token for pasting into `--derp-auth-token`.

### admit-sqlite (net2local.db)

Reads the same protocol's user table from a net2local sqlite
database, merging two sources: the `users` table's enabled rows
(`SELECT name, password FROM users WHERE enable = 1`) and the
`servers` table's enabled rows under their own `username`
(`SELECT username, password FROM servers WHERE enable = 1`) —
people and managed machines share one admission list. On a name
collision a users row wins; blank names and passwords are skipped.

Differences from the users.txt version: the database is re-queried
on every admission check (net2local edits — including disabling a
row — take effect on the next check), and instead of mtime
tracking the last good table serves whenever the database cannot
be read. The database is opened read-only with a busy timeout
(`file:…?mode=ro&_pragma=busy_timeout(5000)`) so admit-sqlite can
never write to the live data. Driver: modernc.org/sqlite (pure Go,
cross-compiles).

## 5. e2e testbed

- `testdata/e2e-derpmap.json` — region 900, node with `IPv4:
  127.0.0.1` (dialed directly), `HostName: local` (TLS SNI only),
  `DERPPort: 14433`, `STUNPort: -1`, `InsecureForTests`.
- `testdata/certs/` — self-signed cert with SAN `local`; derper
  runs `-certmode manual -hostname local`.
- derper requires `-c <config>`; the config is a JSON
  `derpserver.Config` — a private key is mandatory, an empty config
  panics. `/tmp/derper.conf` holds the long-lived test key.
- Typical loop: start `admit`/`admit-sqlite` on 127.0.0.1, start
  the derper with `-verify-client-url` pointing at it, run a
  `tailcat serve` with `--derp-auth-secret-file`, then a client
  `tailcat ping` — correct credentials must print
  `pong … via DERP(e2e)`, wrong ones must 403 in the admit log.
  The rotation fix is verified by letting the startup token expire
  (≥ 2 windows ≈ 10 minutes), restarting only the derper, and
  watching the untouched server readmitted within seconds.

## 6. Operations notes

- Production derper runs with `-verify-client-url` to the local
  admit and fail-open (the default). Switch to
  `-verify-client-url-fail-open=false` if a controller outage must
  block new connections rather than degrade to no admission.
- The derper checks admission once per connection; live connections
  are never re-checked. Disabling a user stops their *new*
  connections immediately.
- Restart order does not matter once all tailcat binaries include
  patch 4: derper restarts are transparent to long-lived clients.
  tailcat binaries built before 2026-10-13 must be restarted once
  (per process) after the derper upgrade to pick up the rotation
  fix.
- `admit -gen` / `admit-sqlite -gen` compute a token locally for
  the manual `--derp-auth-token` flow; the recommended deployment
  is `--derp-auth-secret-file` with automatic rotation, which
  makes `-gen` unnecessary.
