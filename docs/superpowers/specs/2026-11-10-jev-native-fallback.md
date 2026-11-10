# Jev auditor: native fallback on the existing Netcup VPS

## Authorization and boundaries

The user confirmed the existing Netcup VPS is `45.132.246.207` (Coolify) and
approved implementation of an isolated native service, dedicated identities,
systemd/AppArmor, service-owned network rules, one new HTTPS route, and one
reviewed acceptance without paid provider calls. No additional VPS purchase.

The failed Docker/Bubblewrap acceptance is terminal and must not be retried.
Existing applications, Docker/UFW tables, host DNS, global sysctls, and existing
Coolify routes must remain unchanged. No privileged worker or global unconfined
setting. Stop if these boundaries cannot be maintained.

## Verified host facts

Ubuntu24.04 AMD64, Python3.12.3, Bubblewrap0.9.0-1ubuntu0.3, AppArmor4,
systemd255, nftables1.0.9. Venv and report libraries already installed.
Eight CPUs, approximately16GiB memory and8GiB available at read-only preflight.
Global unprivileged-userns restriction remains enabled.

Resolver:127.0.0.53:53, canonical file
`/run/systemd/resolve/stub-resolv.conf`. Ports4750/18080/18081 were unused.
Existing Traefik3.6 watches `/data/coolify/proxy/dynamic/`; no proxy restart is
needed for an additive route file. Its current Coolify address is10.0.1.7,
gateway10.0.1.1. `/usr/lib/systemd/systemd-socket-proxyd` is installed.

## Fixed native interfaces

- Runtime: `/opt/jev-audit-native/releases/<source-sha>/`, root-owned/read-only
  to services. Install the application into that release's dedicated venv;
  API and acceptance scripts import the same installed package.
- Persistent data: `/var/lib/jev-audit-native`; acceptance data is separate at
  `/var/lib/jev-audit-native-acceptance`. Secrets: `/etc/jev-audit-native`, root
  mode0600. No secrets in release, wheels, repository, logs or worker mounts.
- Three locked, non-administrative accounts: `jev-audit-api`, `jev-audit-egress`,
  `jev-audit-relay`. Allocate free UIDs only after NSS and actual host/container
  process-UID checks. No fixed UID assumption or reused account ownership.
- API: existing CLI bound only to127.0.0.1:18080. Proxy: pinned stock Smokescreen
  v0.1.0 bound only to127.0.0.1:4750, separate UID, no provider keys.
- Ingress: a new socket-activated `systemd-socket-proxyd` instance at the exact
  private bridge address10.0.1.1:18081 forwards to127.0.0.1:18080. Only Traefik's
  verified address may reach that new port. API has no public listener. Add
  only a new Traefik dynamic file for the auditor hostname after acceptance;
  do not edit existing files, attach networks or recreate existing containers.
  If these private addresses/route feasibility drift, stop before application.

## Required enforcement

Native systemd units have empty capabilities, NoNewPrivileges, bounded CPU/
memory/PIDs, protected filesystem/home, private temporary files and narrowly
chosen address families. API/worker may create only user/PID/IPC/UTS/mount
namespaces; no network/cgroup namespace. Do not invent a syscall allowlist or
reuse Docker/Moby policy claims.

Derive one complete AppArmor4 candidate from the installed Bubblewrap0.9.0
sources and actual native venv/package/resolver/job paths before loading it.
Allow user namespaces only for this service, preserving the host restriction.
No iterative syscall/path widening after acceptance failure.

Use one uniquely named nftables inet table. Other UIDs and unrelated ports
retain accept/continuation behavior. API UID permits only established replies,
127.0.0.1:4750/TCP and127.0.0.53:53/UDP+TCP, then drops remaining IPv4/IPv6.
Relay UID permits only its API loopback destination and replies. Proxy UID
permits resolver and public80/443 with private/reserved/host-address denial;
retain Smokescreen's destination classification and vetted literal-IP dialing.
Limit the new private ingress port to the verified Traefik source. Never flush
or replace Docker/UFW/global tables. Check and apply project-owned rules as a
single transaction before starting workloads.

Persist fail-closed boot ordering through a project-owned firewall oneshot unit,
not the host's global nftables service. API, proxy, relay service and relay
socket depend on this unit; stopping it stops those dependents while retaining
the rules. Its root loader has only the host capability needed to install the
scoped table; workers retain empty capabilities. Refuse an existing table
rather than merging/adopting it. Only explicit rollback after stopping all
owned workloads may remove the owned table. Established-flow allowances apply
only to replies within role chains; original-direction traffic still passes
the role's destination rules. Proxy/relay cannot create namespaces or write
the API store. IPv6 proxy egress is limited to current global unicast space,
with reserved/transition and self-address exclusions.

## Risk-first implementation slices

1. Build a hash-verified binary-wheel/application/proxy bundle locally. Stage
   only fresh owned identities, directories and a root-owned venv on the host.
   No API/proxy/relay units, policy, firewall or public route activation yet.
2. Collect native paths/version/mount facts without a namespace workload;
   finalize complete profiles, units, scoped rules and rollback. Review bytes
   and focused tests, then authorize the single native acceptance.
3. Acceptance uses fake credentials, actual worker/report code, UID/namespace/
   filesystem checks, controlled public proxy traffic and private/direct-egress
   negatives for both families. It does not call paid providers. Failure stops.
4. Only after acceptance: configure dedicated provider/service credentials,
   actual TLS/DNS and existing Vercel bridge; perform the separately authorized
   small real audit and site release. Keep the original SEO tool independent.

## Verification and rollback

Stage and renderer changes have scoped semantic tests; no tests may depend on
hidden recovery files. Runtime and rule manifests must be deterministic and
hash-checked. Validate systemd/nft/AppArmor syntax before service activation.
Reuse unchanged151-test evidence and run reconciled final checks once.

Rollback stops/removes only owned units, profile, inet table, new route and
owned paths/accounts after usage/ownership checks. No recursive broad delete,
package autoremoval, firewall flush, existing app restart or global sysctl edit.
Existing packages remain installed. Preserve sanitized evidence on failure.
