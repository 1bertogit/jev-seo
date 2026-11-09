# Jev egress proxy dependency

This document describes the **staging dependency**, not a deployment approval.
Publication remains gated on the complete Bubblewrap policy and live isolated
egress/DNS tests.

## Image provenance

The image uses the stock Stripe Smokescreen `v0.1.0` release at commit
`609eb8931420453daf5893509be0b25b21bd9edb`, downloaded only from the official
amd64 release asset. The archive SHA-256 is
`4e1e447449e3cc653dae956208588722b5c8fe8ce894f633adc756a851d1ec46`; this is
the archive hash, not the extracted ELF hash. The Docker build verifies the
archive before safely extracting only the regular `smokescreen` binary.

The runtime retains the stock binary and uses numeric UID `10001`, a read-only
root, dropped capabilities, and no-new-privileges. It contains no keys, job
files, repository source, or environment secrets.

## Configuration boundary

The checked-in staging configuration listens on `127.0.0.1:4750`; deployment
must explicitly set an internal-only listener address after the sandbox
topology is approved. Never bind the proxy to `0.0.0.0`, publish a host port,
or attach it to a shared Coolify network.

The app must use only the isolated app network and controlled CoreDNS. The
proxy gets its own internal network plus a dedicated external network for
upstream connections. No host resolver fallback, plaintext upstream, custom
DNS exception, unsafe private-range option, or allow-range override is
permitted.

The proxy's built-in destination classifier is supplemented with the
special-use ranges in `docker/smokescreen.json` and the current deployment
host address `45.132.246.207/32`. If the host address changes, this explicit
deny entry must be updated before use. IPv6 classification remains enabled;
disabling IPv6 on the external Docker network does not replace IP filtering.

The application URL boundary remains limited to ports 80 and 443. Stock
Smokescreen has no general destination-port allowlist, so this document does
not claim that the proxy enforces that application boundary.

## Required deployment shape

- app: isolated network only, controlled CoreDNS, no public listener;
- proxy: internal app-facing network plus its own external network;
- no host ports, public router, shared production network, or persistent
  volume;
- bounded requests, DNS, tunnel, rate, and burst controls from the reviewed
  configuration;
- normal logging only; debug and MITM logging stay disabled because they can
  retain URLs or headers.

Before publication, verify the actual binary help/config parser, startup under
the strict runtime, listener scope, logs, DNS resolution, direct-egress
denials, HTTP/CONNECT behavior, private/reserved/metadata/host/container
denials, redirects, and rebinding. The offline image proof alone is not a
public-readiness or sandbox-policy approval.
