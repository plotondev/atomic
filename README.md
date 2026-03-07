# atomic

Domain based identity for AI agents.

Atomic ties an agent's identity to its domain. `fin.acme.com` becomes the agent's identity the same way an email address is yours.

Humans have email addresses. You see `alice@acme.com` and you know who you're dealing with -- you can send her credentials, verify her messages, trust her identity.

Agents have nothing. They run on servers with no way to prove who they are. Credentials get pasted into `.env` files. Outgoing requests are unverifiable. Moving to a new server means starting over.

```bash
curl -fsSL atomic.bond/install | sh
atomic init --domain fin.acme.com
```

Your agent now has a keypair, a public identity at `/.well-known/agent.json`, an encrypted vault, and a deposit box for receiving secrets. Single binary, runs on the same server as your agent.

## agent.json

```bash
curl https://fin.acme.com/.well-known/agent.json
```

```json
{
	"v": 1,
	"id": "fin.acme.com",
	"public_key": "ed25519:m2UrN...",
	"email": "inbox@fin.acme.com",
	"status": "active",
	"deposit": "https://fin.acme.com/d/",
	"created_at": "2026-03-07T12:00:00Z"
}
```

Anyone can look up your agent's public key and email. The email is always `inbox@{domain}`, not configurable. The root domain redirects here.

## Deposit box

Your agent needs a Stripe key. Instead of someone SSHing in and editing env vars:

```bash
$ atomic deposit-url --label stripe_key --expires 10m
https://fin.acme.com/d/dt_a1b2c3d4e5f6

$ curl -X POST "https://fin.acme.com/d/dt_a1b2c3d4e5f6" -d "sk_live_abc123"
{"status": "deposited", "label": "stripe_key"}

$ atomic vault get stripe_key
sk_live_abc123
```

URL works once, expires in minutes, secret is AES-256-GCM encrypted on disk. Every deposit is logged.

## Magic links

When a service lets agents sign up, it needs to verify the agent actually controls the domain it claims. Magic links solve this the same way DNS TXT records verify domain ownership, but over HTTP.

```bash
# Service gives the agent a verification code: "VERIFY_ABC123"

# Agent hosts it:
$ atomic magic-link host VERIFY_ABC123 --expires 5m
https://fin.acme.com/m/VERIFY_ABC123

# Agent tells the service: "check my domain"

# Service fetches https://fin.acme.com/m/VERIFY_ABC123
{"status": "verified", "code": "VERIFY_ABC123"}
```

The code is one-time use (gone after the first GET) and expires in minutes. If the service also needs an email, it's always `inbox@{domain}` -- listed in agent.json, not configurable.

## Request signing

```bash
$ atomic sign -- curl -X POST https://partner.api.com/transfer -d '{"amount": 5000}'
```

Adds `X-Agent-Id`, `X-Agent-Sig`, and `X-Agent-Sig-Time` headers. The receiving service fetches the agent's public key from `agent.json` and checks the Ed25519 signature:

```python
# Python -- other languages are similar
agent = requests.get(f"https://{agent_id}/.well-known/agent.json").json()
key_bytes = base64.b64decode(agent["public_key"].removeprefix("ed25519:"))
pub_key = Ed25519PublicKey.from_public_bytes(key_bytes)
pub_key.verify(base64.b64decode(signature), f"{sig_time}.{body}".encode())
```

The receiver only needs the public key from `agent.json` and a signature check. No SDK.

## Examples

**Credential handoff** -- ops generates a deposit URL, sends it to whoever has the key, they POST it. The agent picks it up from its vault. No `.env`, no Slack DMs, no SSH.

**Signed API calls** -- your agent calls a partner service. The partner verifies the request came from `fin.acme.com` by checking the signature against the public key in `agent.json`.

**Multiple agents** -- `billing.acme.com`, `support.acme.com`, `research.acme.com`. Each gets its own identity, vault, and deposit box. They verify each other the same way external services do.

**Key rotation** -- generate a new deposit URL, POST the new credential, agent reads it from vault. No restart needed.

## CLI

```
atomic init --domain <domain>                      Create identity, start server
atomic stop                                        Stop the server

atomic whoami                                      Print identity
atomic status                                      Server + vault summary
atomic verify <domain>                             Check another agent

atomic deposit-url --label <name> --expires <t>    Create deposit URL
atomic deposits                                    Audit log

atomic magic-link host <code> --expires <t>        Host a verification code
atomic magic-link list                             Show active codes

atomic vault set <label> <value>                   Store a secret
atomic vault get <label>                           Read a secret
atomic vault list                                  List labels
atomic vault delete <label>                        Remove a secret

atomic sign -- <command>                           Sign outgoing request
atomic key rotate                                  Rotate keypair
atomic key revoke                                  Revoke identity

atomic service install                             Systemd unit
atomic service uninstall                           Remove unit
```

## TLS

Let's Encrypt by default. Or bring your own cert, or skip TLS if you're behind a proxy.

```bash
atomic init --domain fin.acme.com
atomic init --domain fin.acme.com --tls-cert cert.pem --tls-key key.pem
atomic init --domain fin.acme.com --port 8787 --no-tls
```

## Proxy mode

Already running something on 443? Atomic handles identity routes and forwards the rest.

```bash
atomic init --domain fin.acme.com --proxy-to 127.0.0.1:3000
```

## Files

```
~/.atomic/
  credentials       domain + keypair
  agent.json        public identity document
  vault.enc         encrypted secrets
  deposits.log      audit trail
  atomic.pid        PID file
  atomic.log        server logs
  tls/              certificates
```

## What's next

- [x] Magic links -- service gives the agent a code to host at `agent.acme.com/m/{code}`, then verifies it's there. Domain ownership proof over HTTP.
- [ ] NS delegation + hosted subdomains -- `atomic init` prints DNS records. Later, `atomic init --hosted` provisions a subdomain under `atomic.bond`.
- [ ] Agent email -- `fin.acme.com` gets `inbox@fin.acme.com`. Inbound and outbound, signed with the agent's key.
- [ ] Capabilities -- declare what your agent can do in `agent.json`. Services check before granting access.
- [ ] Approval flows -- agent needs permission, creates an approval request, human approves or denies via a link.
- [ ] Agent-to-agent secrets -- encrypt with another agent's public key, deposit directly.
- [ ] Dashboard -- web UI for identity, vault, deposits, and key rotation.

## License

MIT. PRs welcome.

```bash
git clone https://github.com/ploton/atomic.git
cd atomic
cargo build && cargo test
```
