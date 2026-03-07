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
