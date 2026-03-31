# atomic

Domain identity for AI agents.

`fin.acme.com` is the agent. The domain is the identity, same idea as email for humans. Atomic gives the agent a keypair, publishes the public key at `/.well-known/agent.json`, and runs a small HTTPS server for receiving secrets and proving domain ownership.

```bash
curl -fsSL atomic.bond/install | sh
atomic init --domain fin.acme.com
```

One static binary (~4MB), zero cloud accounts. Runs on the same box as the agent.

## agent.json

```bash
curl https://fin.acme.com/.well-known/agent.json
```

```json
{
  "v": 1,
  "id": "fin.acme.com",
  "name": "fin.acme.com",
  "public_key": "ed25519:m2UrN...",
  "status": "active",
  "deposit": "https://fin.acme.com/d/",
  "created_at": "2026-03-07T12:00:00Z"
}
```

`GET /` redirects here. The public key is how other services verify this agent's signatures.

## Deposit box

The agent needs an API key. Instead of pasting it into a `.env`:

```bash
$ atomic deposit-url --label stripe_key --expires 10m
https://fin.acme.com/d/eyJsYWJlbCI6...Rk4

$ curl -X POST "https://fin.acme.com/d/eyJsYWJlbCI6...Rk4" -d "sk_live_abc123"
{"status":"deposited","label":"stripe_key"}

$ atomic vault get stripe_key
sk_live_abc123
```

The URL is Ed25519-signed, works exactly once (nonce-tracked), and caps out at 24 hours. The secret is AES-256-GCM encrypted before it hits disk.

Once a secret is deposited, the agent can use it directly from shell:

```bash
# Use a secret inline
curl -H "Authorization: Bearer $(atomic vault get stripe_key)" https://api.stripe.com/v1/charges

# Export to environment
export OPENAI_API_KEY=$(atomic vault get openai_key)
python agent.py

# List what's in the vault
$ atomic vault list
openai_key
stripe_key
db_password
```

No `.env` files on disk, no secrets in shell history. The agent reads from the vault at runtime.

Deposits are logged with who sent them:

```bash
$ atomic deposits
2026-03-07T21:45:00+00:00  stripe_key
  IP:         203.0.113.42
  User-Agent: curl/8.5.0

$ atomic deposits --label stripe_key
```

## Magic links

Domain verification, like DNS TXT records but over HTTP. A service gives the agent a code, the agent hosts it, the service checks.

```bash
$ atomic magic-link host VERIFY_ABC123 --expires 5m
https://fin.acme.com/m/VERIFY_ABC123

$ curl https://fin.acme.com/m/VERIFY_ABC123
{"status":"verified","code":"VERIFY_ABC123"}
```

One-time use, gone after the first GET, expires in minutes.

## Request signing

```bash
$ atomic sign -- curl -X POST https://partner.api.com/transfer -d '{"amount": 5000}'
```

Adds `X-Agent-Id`, `X-Agent-Sig`, and `X-Agent-Sig-Time` headers. Verification on the receiving end:

```python
agent = requests.get(f"https://{agent_id}/.well-known/agent.json").json()
key_bytes = base64.b64decode(agent["public_key"].removeprefix("ed25519:"))
pub_key = Ed25519PublicKey.from_public_bytes(key_bytes)
pub_key.verify(base64.b64decode(signature), f"{sig_time}.{body}".encode())
```

Four lines. Fetch the public key, check the signature.

## Why not JWTs?

When a human logs into a service, the service issues a token -- a JWT, a session cookie, whatever. The token is a delegated credential: the service says "I checked your password, here's proof you can carry around." Every request sends the token, the service validates its own signature.

Agents don't need that. An agent with a keypair can prove itself on every request by signing it. The service doesn't issue anything -- it just checks the signature against the public key at the agent's domain.

|                  | Human (JWT)                          | Agent (Atomic)                              |
|------------------|--------------------------------------|---------------------------------------------|
| **Identity**     | email + password                     | domain (`fin.acme.com`)                     |
| **Signup**       | create account, get credentials      | sign request + magic link for domain proof  |
| **Proof**        | service issues a JWT                 | agent signs every request with private key  |
| **Each request** | send JWT, service checks it          | send signature, service checks agent.json   |
| **Expiry**       | token expires, agent re-auths        | no token -- signatures are stateless        |
| **Revocation**   | service invalidates the token        | agent.json status changes to `"revoked"`    |
| **Rotation**     | service issues new token             | agent rotates keypair, agent.json updates   |
| **Storage**      | agent stores token, handles refresh  | private key stays on disk, nothing to refresh |

The practical difference: the agent has nothing to manage. No token storage, no refresh logic. The private key stays on the box and never gets sent over the wire.

A service that wants extra assurance can layer a magic link challenge on top of the signature check at signup -- verify the sig, then confirm domain control, then create an internal account for `fin.acme.com`. After that, subsequent requests are just signature checks against a cached public key.

Performance-wise, JWT verification is a single HMAC check while Ed25519 verify costs more. But "more" here means microseconds, and the public key only changes on rotation so it caches well. It's not where your latency lives.

## CLI

```
atomic init --domain <domain>                      Create identity, start server
atomic serve                                       Run server in foreground
atomic stop                                        Stop the server

atomic whoami                                      Print identity
atomic status                                      Server + vault summary
atomic verify <domain>                             Check another agent

atomic deposit-url --label <name> --expires <t>    Create deposit URL
atomic deposits [--label <name>]                   Deposit audit log

atomic magic-link host <code> --expires <t>        Host a verification code
atomic magic-link list                             Show active codes

atomic vault set <label> <value>                   Store a secret
atomic vault get <label>                           Read a secret
atomic vault list                                  List labels
atomic vault delete <label>                        Remove a secret

atomic sign [--dry-run] -- <command>               Sign outgoing request
atomic key rotate                                  Rotate keypair
atomic key revoke                                  Revoke identity

atomic service install                             Systemd unit
atomic service uninstall                           Remove unit
atomic service status                              Show service status
```

## TLS

Auto-TLS via acme.sh (Let's Encrypt) by default. BYO cert or skip TLS if you're behind a proxy.

```bash
atomic init --domain fin.acme.com                                          # auto-TLS
atomic init --domain fin.acme.com --tls-cert cert.pem --tls-key key.pem    # your cert
atomic init --domain fin.acme.com --port 8787 --no-tls                     # behind proxy
```

HSTS is set when TLS is active.

## Security

Private key stored at 600 permissions, never leaves the box. Vault uses AES-256-GCM with a key derived from the private key via HKDF -- separate from the signing key.

Deposit tokens are Ed25519-signed with a nonce and a 24h max TTL. Every failure returns 404 regardless of the reason, so you can't probe for valid tokens. Body size is capped at 1MB.

All responses get `nosniff`, `no-store`, and `no-referrer` headers. HSTS (2-year max-age) when TLS is on. SQL is parameterized everywhere (SQLite in WAL mode).

## Files

```
~/.atomic/
  credentials       domain + keypair (600 perms)
  agent.json        public identity document
  atomic.db         SQLite (vault, deposits, magic links)
  atomic.pid        server PID
  atomic.log        server logs
  tls/              certificates
```

## Build

```bash
git clone https://github.com/ploton/atomic.git
cd atomic
cargo build --release    # ~4MB binary
cargo test               # 65 tests
```

Cross-compiles to `x86_64-linux-musl`, `aarch64-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.

## Changelog

**e3eb87e** — Hard conn lifetime, WAL checkpoint timeout, vault label validation, jemalloc default
- `PooledConn::drop` force-closes connections held >60s instead of returning to pool (prevents leaks from panicked threads or stuck queries)
- Final WAL checkpoint wrapped in 5s `tokio::time::timeout` to prevent indefinite hang on shutdown if DB is stuck
- `vault::cmd_set` validates labels with printable ASCII check (defense-in-depth, matching server-side `is_valid_input`)
- jemalloc is now the default feature (`cargo build` enables it; `--no-default-features` to opt out)

**1ba345e** — DashMap rate limiter, flock PID locking, jemalloc opt-in, connection leak detection
- Replace `Mutex<HashMap>` rate limiter with `DashMap` (sharded locks, no global contention under high concurrency)
- PID file locking via `flock` prevents double-start races; lock auto-released on crash by kernel
- Optional jemalloc allocator (`--features jemalloc`) for long-lived Linux deployments to prevent RSS bloat
- `PooledConn` tracks hold time, warns on connections held >30s (leak detection)
- Panic hook cleans up PID file on fatal panic
- `PRAGMA optimize` added to hourly cleanup for SQLite query planner stats
- Rate limiter eviction moved from hot path to background cleanup (`DashMap::len()` check replaces per-request `retain`)

**a609534** — Exponential backoff for supervised tasks, deposit_log retention
- `spawn_supervised` uses exponential backoff (5s → 10s → ... → 320s cap) instead of fixed 5s delay to prevent spin loops on persistent failures (e.g. disk full)
- Cleanup task purges `deposit_log` entries older than 90 days to prevent unbounded disk growth on long-lived servers

**fdee3d2** — Harden server: 404-everything, SIGTERM/SIGHUP handling, shutdown WAL checkpoint, ciphertext size limit, SQLite mmap
- All HTTP error paths return 404 (no 500s) to prevent information leakage
- `shutdown_signal()` handles SIGTERM (from `atomic stop`) and SIGINT
- `kill -HUP` triggers immediate TLS cert reload on Unix (zero-delay vs 12h poll)
- Final WAL checkpoint (TRUNCATE) on shutdown for data integrity
- Graceful shutdown timeout 10s → 30s for slow-disk WAL merge
- `decrypt()` rejects ciphertext >16MB before allocation (resource exhaustion defense)
- SQLite: `wal_autocheckpoint=1000` pages, `mmap_size=64MB` for read throughput

**a7d7afb** — Resilience hardening: supervised tasks, health endpoint, input validation, SQLite tuning
- Background tasks (WAL checkpoint, DB cleanup) auto-restart on panic with 5s backoff
- `/_/health` endpoint: checks DB + agent.json, returns 200/503 for load balancer integration
- Input validation rejects non-printable chars and labels > 256 bytes on deposit and magic link paths
- SQLite page cache bumped to 64MB, temp tables stored in memory
- X-Forwarded-For warning when header present but `behind_proxy=false` (misconfiguration detection)
- Mutex poisoning recovery uses `into_inner()` consistently across all lock sites

**fcfffe5** — Production hardening: SQLite resilience, fsync durability, WAL checkpointing, zeroize decrypt output
- SQLite: `busy_timeout=5s`, `journal_size_limit=64MB`, `synchronous=NORMAL` (WAL-safe)
- Atomic writes: fsync data + parent directory on Unix for crash safety
- Background WAL checkpoint (TRUNCATE) every 5 min to cap disk growth
- X-Forwarded-For IP validation to reject spoofed non-IP values
- `decrypt()` returns `Zeroizing<Vec<u8>>` — plaintext wiped from memory on drop

**a3f4688** — Rate limiter GC, supervisor circuit breaker, WAL checkpoint strategy, PID race fix
- Rate limiter evicts stale entries on every access (bounded memory under DDoS/IPv6 scanning)
- Supervisor circuit breaker: process aborts after 5 restarts in 5 minutes (prevents resource exhaustion on unrecoverable errors)
- WAL checkpointing split: PASSIVE every 5m (non-blocking), TRUNCATE hourly (reclaims disk)
- `atomic stop`: kill -0 probe before SIGTERM to minimize PID reuse race window

**1b65780** — Connection pool, handler timeouts, credential zeroize, startup guards
- Replace `Mutex<Connection>` with zero-dep channel-based `DbPool` (4 conns), unlocking WAL concurrent readers
- Wrap handler DB ops in `tokio::time::timeout(5s)` to prevent unbounded task accumulation
- Lower SQLite `busy_timeout` to 4s (below tokio 5s) for clean BUSY errors before task cancellation
- Zeroize credential JSON buffer in `save()` via `Zeroizing<Vec<u8>>` — private key material no longer lingers in freed heap
- Startup guard: warn if `RLIMIT_NOFILE < 4096` (prevents cryptic fd exhaustion under TLS load)
- Startup guard: warn if log file exceeds 100MB (prevents disk-full failures on vault atomic writes)

**7b45baf** — Replace exit(1) circuit breaker with max backoff, monotonic rate limiter, bounded pool
- Circuit breaker no longer calls `process::exit(1)` — enters 320s max backoff instead, so destructors run (Zeroizing wipes vault keys, final WAL checkpoint completes)
- Rate limiter uses monotonic `Instant` instead of wall-clock `i64` timestamps, preventing clock-skew manipulation of rate windows
- Rate limiter eviction split into dedicated 5-minute task (was hourly), bounding DashMap memory under sustained attack
- Connection pool uses bounded `sync_channel(size)` instead of unbounded `channel()` for explicit capacity enforcement

**5fc281e** — AES-GCM zeroize, dynamic pool sizing, health check WAL monitor
- Enable `zeroize` feature on `aes-gcm`: AES key schedule is now wiped from memory on cipher drop
- DB connection pool sized dynamically via `available_parallelism()` (clamped 2..8) instead of hardcoded 4
- Health endpoint (`/_/health`) now reports WAL file size, returns degraded if WAL exceeds 50MB

## Roadmap

- [x] Identity (agent.json + Ed25519)
- [x] Deposit box (signed URLs, encrypted vault, audit log)
- [x] Magic links (domain verification)
- [x] Request signing
- [x] Auto-TLS
- [ ] NS delegation + hosted subdomains
- [ ] Agent email
- [ ] Capability declarations
- [ ] Approval flows
- [ ] Agent-to-agent secrets
- [ ] Dashboard

## License

MIT
