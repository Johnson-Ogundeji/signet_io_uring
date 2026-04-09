# Security Policy

## Supported Versions

**Signet_io_uring** is in **alpha**. Only the `main` branch and the most
recent tagged release receive security fixes.

| Version       | Supported |
|---------------|-----------|
| `main`        | Yes       |
| `0.1.0-alpha` | Yes       |
| `< 0.1.0`     | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security problems.**

Please use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in a description, reproduction steps, and the affected version /
   commit.

If GitHub private advisories are unavailable to you, you can instead email
the maintainer listed in the repository profile. Please encrypt sensitive
details with the maintainer's public key when possible.

You should expect:

- An acknowledgement within **3 business days**.
- A triage decision (accepted / needs more info / not a vulnerability) within
  **10 business days**.
- For accepted issues, a coordinated disclosure timeline that gives downstream
  users time to upgrade before the details are made public.

## Scope

In scope:

- Memory safety bugs (UAF, double-free, OOB read/write, integer overflow that
  leads to one of the above).
- TLS handshake / certificate verification bypasses.
- WebSocket framing or fragmentation logic that allows protocol smuggling or
  desynchronization.
- `io_uring` SQE construction bugs that pass uninitialized or invalid data to
  the kernel.

Out of scope:

- Bugs that require an attacker who already has local code execution or
  filesystem write access on the host.
- DoS via `permessage-deflate` decompression bombs *if* the consumer has not
  configured `max_message_size` — this is documented as the consumer's
  responsibility.
- Reports against the example clients in `examples/` (they are illustrative,
  not production code).

## Security Audit

Signet has undergone a full internal security audit. The complete report,
including all 47 issues identified and the status of each, is available at
[`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md).
