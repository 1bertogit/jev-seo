# Jev Bubblewrap sandbox policy candidate

**Status: NOT APPROVED FOR DEPLOY.** This is one offline candidate for
parent/oracle review. It has not been loaded into a kernel, Docker, or a
production host, and no live canary was attempted.

## Pinned provenance

| Artifact | URL / identity | SHA-256 |
| --- | --- | --- |
| Docker seccomp baseline | `https://raw.githubusercontent.com/moby/moby/464cd50/vendor/github.com/moby/profiles/seccomp/default.json` | `536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74` raw; `9da637d2ab0a204fcbd91bd88f1be9e004a3acab61c571a9f5b8870e588a17d2` canonical JSON |
| Bubblewrap v0.8.0 source | `https://raw.githubusercontent.com/containers/bubblewrap/v0.8.0/bubblewrap.c`; tag object `38b25c808ac5fe87db27a3c3b1f9bf54b1b180ce` | `ac0c67ec07c220c419d64dc100e16650f3d7cccb221285f523613ab88755f6eb` |
| Bubblewrap bind helper | `https://raw.githubusercontent.com/containers/bubblewrap/v0.8.0/bind-mount.c` | `488847bd99903180499909dc408913265f632d36356f2621b89708aade876d80` |
| Bubblewrap utility helper | `https://raw.githubusercontent.com/containers/bubblewrap/v0.8.0/utils.c` | `33ff3568942086e2539c118e97f340e163adc92fdd4c286b5606de4e7681162a` |
| Moby AppArmor template | `https://raw.githubusercontent.com/moby/profiles/61eaf32614c7/apparmor/template.go` | `cce1c730656ad73cb04b19bf25caa2351732a00e04a06eeaf3010105e1ba6a57` |
| Moby AppArmor generator defaults | `https://raw.githubusercontent.com/moby/profiles/61eaf32614c7/apparmor/apparmor.go` | `0cda3c9fd08d39493afbd445553333a75ac05feadf7d9aad55596b446c9343c6` |
| Debian O_PATH backport | `bubblewrap_0.8.0-2+deb12u1.debian.tar.xz`, `Add-bind-fd-and-ro-bind-fd-to-let-you-bind-a-O_PATH-fd.patch` | tar `37917e8abdd6df1d1118f089e9cf1f9374e1b5bb21c8a70d7de4e9b5dfb10f6d`; patch `f7419666dcd2968dffb49e29f2400bb7f26b362ae748b1be499a3bf27fcaceb4` |

The sources were fetched only into the approved disposable temporary root
`/Volumes/SSD_Samsung/.dev-cache/tmp/opencode/jev-sandbox-sources`. No source
was added to this worktree and no remote host was accessed.

The retained runtime image is immutable digest
`sha256:654baccf4ddb0518ff84ca1b3a9d4243ea197058d198a4854c8daf6c0dbc15b6`.
The local Docker host is ARM64, so this AMD64 image was inspected through
emulation only; that is not runtime policy validation. The profile is pinned to
AMD64 for every newly allowed syscall rule. It never adds Docker
`CAP_SYS_ADMIN`, `privileged`, a network/cgroup namespace, or a generic
`/proc/self/fd/**` permission.

## Fixed runner invocation

The local source of truth is `jevseo/web/runner.py`:

- `_ro_mounts`: `runner.py:119-138`; `_build_bwrap_argv()` uses
  `Path.resolve()` only for the forbidden-root safety filter, passes the
  original fixed source strings, and keeps each target fixed.
- `_build_bwrap_argv`: `runner.py:141-177`; the fixed options are
  `--unshare-user`, `--unshare-pid`, `--unshare-ipc`, `--unshare-uts`,
  `--cap-drop ALL`, `--proc /proc`, `--dev /dev`, `--tmpfs /tmp`, one job
  `--bind`, fixed `--ro-bind` entries, and no network/cgroup namespace flags.
- Job id validation: `runner.py:46`, `^[0-9a-f]{32}$`.

Bubblewrap's actual setup paths are not the final runner paths during setup.
Before the first pivot, its root tmpfs is mounted at `/tmp`, and it self-binds
`/tmp/newroot`. After that pivot, `setup_newroot()` prefixes destinations with
`/newroot/` and sources with `/oldroot/` (`bubblewrap.c:948-950`,
`bubblewrap.c:1187-1219`, `utils.c:825-830`). Before setup, Bubblewrap's
`resolve_symlinks_in_ops()` applies `realpath()` to bind sources
(`bubblewrap.c:1515-1555`); the runner's `.resolve()` is only its safety check.
The bind helper is
`bind_mount()` at `bind-mount.c:377-488`. That is why the AppArmor rules
use `/newroot/proc`, `/newroot/dev`, `/newroot/tmp`, and `/oldroot/...` rather
than the final process-visible paths.

For the Bookworm image, the fixed runner destinations include `/usr`, `/bin`,
`/lib`, `/lib64`, `/usr/share/fonts`, `/usr/local/share/fonts`, `/etc/fonts`,
the three fixed resolver/host files, `/etc/ssl/certs`, `/usr/local`,
`/usr/local/bin`, and `/runtime/jevseo`. `/usr/local` is required because the
runner explicitly adds `sys.prefix` (`runner.py:127-129`). Nonexistent optional
font paths are skipped by `_ro_mounts()` and do not create dynamic permissions.

## Seccomp delta

`docker/security/jev-bwrap-seccomp.json` consists of the pinned Docker default
profile followed by exactly these thirteen AMD64-only rules. The static test
removes these exact thirteen rules and verifies the canonical baseline hash above; it
does not read a hidden baseline fixture or the report.

The manifest keys are: root recursive slave; tmpfs; recursive bind; read-only
bind remount and writable-job remounts; proc/devpts; newroot self-bind; oldroot recursive
private; `pivot_root`; `umount2 MNT_DETACH`; the exact second-userns
`unshare(CLONE_NEWUSER)`; and the existing clone exception.

The read-only bind remount rule is a single masked comparison on mount arg 3;
the writable job remount is a separate single masked comparison.

| Rule | Source operation and flags | Why required |
| --- | --- | --- |
| `mount` arg 3 `573440` (`0x8c000`) | `bubblewrap.c:3052-3056`: `MS_SILENT\|MS_SLAVE\|MS_REC` on `/` | Prevent mount propagation to the outer namespace. |
| `mount` arg 3 `6` (`0x6`) | `bubblewrap.c:3058-3060`, `bubblewrap.c:1134-1141`: tmpfs `MS_NODEV\|MS_NOSUID` | Create the setup root tmpfs and fixed `/tmp`/`/dev` tmpfs mounts. |
| `mount` arg 3 `53248` (`0xd000`) | `bind-mount.c:396-399`: `MS_SILENT\|MS_BIND\|MS_REC` | Recursive fixed job/runtime/package/device binds only. |
| `mount` RO masked rule | `bind-mount.c:449-453,469-473`: `MS_SILENT\|MS_BIND\|MS_REMOUNT` plus dynamic current flags and mandatory `MS_RDONLY\|MS_NOSUID\|MS_NODEV` | Read-only bind remounts only. One arg-3 comparison uses datum `0x9027` and mask `0xffffffffffdff3f7`; current flags are limited to the helper's parsed `ro,nosuid,nodev,noexec,noatime,nodiratime,relatime` set (`bind-mount.c:82-125`). |
| `mount` job masked rule | `bind-mount.c:449-453`: writable `--bind` still adds `MS_NOSUID\|MS_NODEV` when needed | One arg-3 comparison uses datum `0x9026` and the same mask. AppArmor bounds it to `/newroot/job/`; it does not grant a general writable remount. |
| `mount` arg 3 `14` (`0xe`) | `bubblewrap.c:1120-1123`: proc `MS_NOSUID\|MS_NOEXEC\|MS_NODEV` | Create the private proc mount required by `--unshare-pid --proc`. |
| `mount` arg 3 `10` (`0xa`) | `bubblewrap.c:1145-1149`: devpts `MS_NOSUID\|MS_NOEXEC` | Create the devpts instance required by `--dev`. |
| `mount` arg 3 `3236810752` (`0xc0edd000`) | `bubblewrap.c:3069-3079`: `MS_SILENT\|MS_MGC_VAL\|MS_BIND\|MS_REC` self-bind of `newroot`; `MS_MGC_VAL=0xc0ed0000` | Make the new root a mount point before the first pivot. |
| `mount` arg 3 `311296` (`0x4c000`) | `bubblewrap.c:3143-3145`: `MS_SILENT\|MS_REC\|MS_PRIVATE` on oldroot | Stop teardown propagation. |
| `pivot_root` | `bubblewrap.c:3081-3085` and `bubblewrap.c:3156-3172`: the two fixed pivots | Complete the root transition; AppArmor bounds both path pairs. |
| `umount2` arg 1 equals `2` | `bubblewrap.c:3147` and `bubblewrap.c:3173-3176`: `MNT_DETACH` only | Detach only the two fixed old-root mounts. |
| AMD64 `unshare` arg 0 equals `268435456` (`0x10000000`) | `bubblewrap.c:3184-3214`: second `unshare(CLONE_NEWUSER)` needed by `--dev` after the first user namespace | Permit only the exact second user-namespace operation; no general `unshare`, `setns`, network namespace, or cgroup namespace rule is added. |
| AMD64 `clone` exception | Parent's exact namespace-free clone delta | Permit the fixed bwrap clone shape without arbitrary clone flags. |

The read-only remount mask is derived, not guessed: mandatory bits are
`0x9027` (`MS_SILENT|MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV`) for
read-only binds and `0x9026` for the writable job bind. Optional bits are
`0x200c08` (`MS_NOEXEC|MS_NOATIME|MS_NODIRATIME|MS_RELATIME`), and the single
64-bit comparison mask is `0xffffffffffdff3f7`; its complement rejects all
other bits. `MS_REC` is intentionally not asserted for remounts because
`bind-mount.c` explicitly remounts each recursive submount separately and does
not pass `MS_REC`. Each seccomp rule has unique argument indexes because
libseccomp accepts at most one comparison per argument per rule.

## AppArmor rendering and path bounds

`jev-bwrap.apparmor` is rendered from the actual pinned Moby
`apparmor/baseTemplate` with `abi <abi/3.0>`, `#include <tunables/global>`,
and `#include <abstractions/base>`. The exact template inventory is retained:

- `network,`, `deny network alg,`, and `deny network vsock,`;
- `capability,`, `file,`, all five signal peer rules (including runc, crun,
  and the daemon peer), the complete template `/proc` and `/sys` denies;
- `ptrace (trace,tracedby,read,readby) peer="jev-audit-bwrap"`.

The Moby generator uses `unconfined` when the daemon profile is unavailable
(`apparmor.go:45-47`); that is rendered as `peer="unconfined"` and remains an
explicit pre-deploy verification assumption. Only the template's generic `deny mount,` and
`umount,` entries are replaced. There is no attachment path.

The candidate's mount/path restrictions are:

- exact setup mounts `/`, `/tmp`, `/tmp/newroot`, `/newroot/proc`,
  `/newroot/dev`, `/newroot/tmp`, and `/newroot/dev/pts`;
- AppArmor bind mediation matches `rbind` for the helper's bind operations;
  `MS_SILENT` is present in the syscall/seccomp flags but is not included in
  the kernel bind-mediation flag set, so no inaccurate `rbind,silent` rule is
  used;
- the only writable job source is
  `/oldroot/data/jobs/[0-9a-f]` repeated exactly 32 times, to `/newroot/job/`,
  followed only by the nosuid/nodev job remount;
- fixed canonical runtime/package sources and fixed targets only, plus the six
  explicit `/oldroot/dev/{null,zero,full,random,urandom,tty}` device binds;
- `/oldroot/usr/local/` is bound to `/newroot/usr/local/` and has the same
  read-only remount as the other runtime roots;
- `setup_newroot()` first recursively self-binds exactly
  `/newroot/proc/sys/`, `/newroot/proc/sysrq-trigger`,
  `/newroot/proc/irq/`, and `/newroot/proc/bus/`, then remounts those paths
  read-only. The `sysrq-trigger` operation is passed by Bubblewrap without a
  trailing slash (`strconcat3(dest, "/", cover_proc_dirs[i])` at
  `bubblewrap.c:1270-1285`).
- read-only remounts use the mandatory privilege-reducing flag set and the
  helper-derived optional flags only, on explicit fixed targets;
- pivots are exactly `pivot_root oldroot=/tmp/oldroot/ /tmp/` and
  `pivot_root oldroot=/newroot/ /newroot/`; unmounts are exactly `/oldroot/`
  and `/`.

The Debian `0.8.0-2+deb12u1` patch adds `--bind-fd` and `--ro-bind-fd`, but
the fixed runner invokes neither. Upstream v0.8.0 still opens the destination
with `O_PATH` and reads `/oldroot/proc/self/fd/N` for mount-table resolution
  (`bind-mount.c:402-438`). No `/proc/self/fd/**` wildcard is granted. If a
target ABI mediates that internal readlink in a way the explicit rules cannot
express, the safe result is rejection of this candidate rather than a broad
source permission.

## Offline validation gates

1. Run the focused static test; it must not fetch sources or read any
   `.superpowers` baseline/report fixture.
2. Compile this profile in a disposable local Ubuntu 24.04 image with the
   packaged `apparmor_parser`, `--skip-kernel-load`, and no host profile load.
3. Verify the parser image digest, parser ABI, source hashes, and the complete
   template semantic inventory. Parser compilation does not prove target-kernel
   semantics for `options in (...)` matching.
4. If the retained image's existing `libseccomp.so.2` and Python are available,
   construct the appended rules with `seccomp_rule_add_array()` and export BPF
   to an anonymous file descriptor without calling `seccomp_load`; this checks
   rule construction only.
5. Accept only the retained immutable runtime image digest after reviewing its
   architecture, Bubblewrap package/version/path, and mount manifest. The
   strict local inspection of the retained image observed AMD64 under ARM64
   emulation, Bubblewrap `0.8.0` at `/usr/bin/bwrap`, and `/dev` as
   `rw,nosuid` tmpfs with recursive submounts `/dev/mqueue`, `/dev/pts`, and
   `/dev/shm`; it did not justify any device-node remount permission. Any
   mismatch or expected dynamic mount property requiring remote preflight is a
   rejection/gate, not a reason to broaden this policy.
6. No SSH, remote action, production runtime permission, or live canary is part
   of this candidate.

Until all gates and parent/oracle review pass, this remains **NOT APPROVED FOR
DEPLOY**.
