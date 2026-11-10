"""Focused offline tests for native bundle provenance and staging planning."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


BUILD = load("native_build", ROOT / "deploy/native/build_bundle.py")
STAGE = load("native_stage", ROOT / "deploy/native/stage.py")
SOURCE_SHA = BUILD.APP_SOURCE_SHA
NATIVE_MEMBER = "native-inputs/deploy/native/input"
NATIVE_DATA = b"reviewed"
NATIVE_MANIFEST = json.dumps({"format": 1, "inputs": [{"member": NATIVE_MEMBER, "source": "deploy/native/input", "sha256": hashlib.sha256(NATIVE_DATA).hexdigest()}]}, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def valid_payload() -> dict[str, bytes]:
    return {
        "requirements.lock": b"jev-seo==0.1.1 --hash=sha256:" + b"0" * 64 + b"\n",
        "source/jevseo/x.py": b"x",
        "native/smokescreen": b"\x7fELF",
        "native/smokescreen.json": b"{}",
        "native/tools/check_sandbox_acceptance.py": b"# reviewed",
        "native-inputs/manifest.json": NATIVE_MANIFEST,
        NATIVE_MEMBER: NATIVE_DATA,
        "wheelhouse/jev_seo-0.1.1-py3-none-any.whl": b"wheel",
    }


def make_bundle(path: Path, payload: dict[str, bytes], source_sha: str = SOURCE_SHA) -> None:
    manifest = "".join(f"{hashlib.sha256(value).hexdigest()}  {name}\n" for name, value in sorted(payload.items()))
    marker = json.dumps({"format": 1, "source_sha": source_sha, "manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest()}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with tarfile.open(path, "w:gz") as tar:
        for name, data in {**payload, "manifest.sha256": manifest.encode(), "bundle.marker": marker}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))


class NativeStageTests(unittest.TestCase):
    def test_host_versions_accepts_actual_ubuntu_output_and_rejects_drift(self):
        output = [
            "Python 3.12.3", "0.9.0-1ubuntu0.3", "bubblewrap 0.9.0",
            "systemd 255 (255.4-1ubuntu8.18)",
            "nftables v1.0.9 (Old Doc Yak #3)",
            "AppArmor parser version 4.0.1",
        ]
        with mock.patch.object(STAGE, "_command", side_effect=output):
            self.assertEqual(STAGE.host_versions()["nft"], output[4])
        output[4] = "nftables v1.0.10"
        with mock.patch.object(STAGE, "_command", side_effect=output):
            with self.assertRaisesRegex(STAGE.StageError, "host_version_drift"):
                STAGE.host_versions()

    def test_source_allowlist_excludes_env_git_and_generated_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "jevseo").mkdir()
            (root / "jevseo/__init__.py").write_text("__version__='x'", encoding="utf-8")
            (root / "jevseo/__pycache__").mkdir()
            (root / "jevseo/__pycache__/bad.pyc").write_bytes(b"bad")
            (root / ".env").write_text("SECRET=never", encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git/config").write_text("private", encoding="utf-8")
            for name in ("pyproject.toml", "README.md", "LICENSE"):
                (root / name).write_text(name, encoding="utf-8")
            (root / "docker").mkdir()
            (root / "docker/smokescreen.json").write_text("{}", encoding="utf-8")
            (root / "docker/check_sandbox_acceptance.py").write_text("# reviewed", encoding="utf-8")
            native = root / "deploy/native/native-input.txt"
            native.parent.mkdir(parents=True)
            native.write_text("reviewed", encoding="utf-8")
            tracked = {"jevseo/__init__.py", "pyproject.toml", "README.md", "LICENSE"}
            with mock.patch.object(BUILD, "_git_source_paths", return_value=tracked):
                files = BUILD.collect_source(root, [Path("deploy/native/native-input.txt")])
            self.assertIn("source/jevseo/__init__.py", files)
            self.assertIn("native-inputs/manifest.json", files)
            self.assertNotIn("source/.env", files)
            self.assertFalse(any(".git" in name or "__pycache__" in name for name in files))
            with mock.patch.object(BUILD, "_git_source_paths", return_value=tracked):
                with self.assertRaises(BUILD.BundleError):
                    BUILD.collect_source(root, [])

    def test_source_symlink_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "jevseo").mkdir()
            (root / "jevseo/a.py").write_text("x", encoding="utf-8")
            (root / "jevseo/link.py").symlink_to(root / "jevseo/a.py")
            os.link(root / "jevseo/a.py", root / "jevseo/hard.py")
            for name in ("pyproject.toml", "README.md", "LICENSE"):
                (root / name).write_text(name, encoding="utf-8")
            (root / "docker").mkdir()
            (root / "docker/smokescreen.json").write_text("{}", encoding="utf-8")
            (root / "docker/check_sandbox_acceptance.py").write_text("# reviewed", encoding="utf-8")
            native = root / "deploy/native/input"
            native.parent.mkdir(parents=True)
            native.write_text("x", encoding="utf-8")
            tracked = {"jevseo/a.py", "jevseo/link.py", "jevseo/hard.py", "pyproject.toml", "README.md", "LICENSE"}
            with mock.patch.object(BUILD, "_git_source_paths", return_value=tracked):
                with self.assertRaises(BUILD.BundleError):
                    BUILD.collect_source(root, [Path("deploy/native/input")])
            (root / "jevseo/hard.py").unlink()
            tracked.remove("jevseo/hard.py")
            with mock.patch.object(BUILD, "_git_source_paths", return_value=tracked):
                with self.assertRaises(BUILD.BundleError):
                    BUILD.collect_source(root, [Path("deploy/native/input")])

    def test_uid_allocator_uses_free_dynamic_candidates_and_skips_shared_uid(self):
        self.assertEqual(STAGE.allocate_uids({200, 202, 10001}, 3, (200, 205)), [201, 203, 204])

    def test_process_inventory_collects_all_uid_gid_and_group_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp) / "proc"
            status = proc / "123" / "status"
            status.parent.mkdir(parents=True)
            status.write_text("Uid:\t301\t302\t303\t304\nGid:\t401\t402\t403\t404\nGroups:\t501\t502\n", encoding="ascii")
            self.assertEqual(STAGE.process_uids(proc), {301, 302, 303, 304, 401, 402, 403, 404, 501, 502})

    def test_bundle_marker_manifest_and_all_hashes_verify_before_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "bundle.tar.gz"
            payload = valid_payload()
            BUILD.make_archive(archive, payload, SOURCE_SHA)
            source, payload = STAGE.verify_bundle(archive)
            self.assertEqual(source, SOURCE_SHA)
            self.assertEqual(payload["source/jevseo/x.py"], b"x")

    def test_traversal_and_nonregular_members_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            traversal = Path(temp) / "traversal.tar.gz"
            with tarfile.open(traversal, "w:gz") as tar:
                info = tarfile.TarInfo("../escape")
                info.size = 1
                tar.addfile(info, io.BytesIO(b"x"))
            with self.assertRaises(STAGE.StageError):
                STAGE.verify_bundle(traversal)
            symlink = Path(temp) / "symlink.tar.gz"
            payload = {"native-inputs/x": b"x"}
            manifest = f"{hashlib.sha256(b'x').hexdigest()}  native-inputs/x\n"
            marker = json.dumps({"format": 1, "source_sha": SOURCE_SHA, "manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest()}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            with tarfile.open(symlink, "w:gz") as tar:
                for name, data in {**payload, "manifest.sha256": manifest.encode(), "bundle.marker": marker}.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
                info = tarfile.TarInfo("native-inputs/link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tar.addfile(info)
            with self.assertRaises(STAGE.StageError):
                STAGE.verify_bundle(symlink)

    def test_unexpected_payload_prefix_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "unexpected.tar.gz"
            payload = valid_payload()
            payload["native/unreviewed"] = b"x"
            BUILD.make_archive(archive, payload, SOURCE_SHA)
            with self.assertRaises(STAGE.StageError):
                STAGE.verify_bundle(archive)

    def test_smokescreen_download_is_official_hash_checked_and_never_executed(self):
        data = b"asset"

        class Response:
            sent = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                if self.sent:
                    return b""
                self.sent = True
                return data

        with tempfile.TemporaryDirectory() as temp, mock.patch.object(BUILD, "SMOKESCREEN_SIZE", len(data)), mock.patch.object(BUILD, "SMOKESCREEN_SHA256", hashlib.sha256(data).hexdigest()):
            destination = Path(temp) / "asset.tar.gz"
            with mock.patch.object(BUILD.urllib.request, "urlopen", return_value=Response()) as opener:
                BUILD.download_smokescreen(destination)
            self.assertEqual(opener.call_args.args[0], BUILD.SMOKESCREEN_URL)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_offline_install_command_has_no_online_fallback(self):
        command = STAGE.offline_install_command(Path("/release/venv/bin/python"), Path("/release"))
        self.assertIn("--no-index", command)
        self.assertIn("--require-hashes", command)
        self.assertIn("--only-binary=:all:", command)
        self.assertNotIn("--index-url", command)

    def test_activation_commands_are_forbidden(self):
        with self.assertRaises(STAGE.StageError):
            STAGE._command(["systemctl", "start", "jev-audit-api.service"])
        with self.assertRaises(STAGE.StageError):
            STAGE._command(["nft", "flush", "ruleset"])

    def test_dry_run_is_apply_guarded_and_returns_safe_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            resolver = base / "stub-resolv.conf"
            resolver.write_text("nameserver 127.0.0.53\n", encoding="ascii")
            patches = {
                "NATIVE_ROOT": base / "native",
                "RELEASES_ROOT": base / "native/releases",
                "DATA_ROOT": base / "data",
                "ACCEPTANCE_ROOT": base / "acceptance",
                "CONFIG_ROOT": base / "config",
                "RESOLVER_PATH": resolver,
                "DISK_ANCHORS": (base,),
            }
            payload = valid_payload()
            with mock.patch.multiple(STAGE, **patches), mock.patch.object(STAGE, "verify_bundle", return_value=(SOURCE_SHA, payload)), mock.patch.object(STAGE, "host_versions", return_value={"python": "Python 3.12.3"}), mock.patch.object(STAGE, "validate_prerequisites"), mock.patch.object(STAGE, "validate_paths"), mock.patch.object(STAGE, "disk_anchor", return_value=base), mock.patch.object(STAGE.shutil, "disk_usage", return_value=SimpleNamespace(free=STAGE.MIN_FREE_BYTES + STAGE.MAX_HEADROOM_BYTES)), mock.patch.object(STAGE, "validate_accounts"), mock.patch.object(STAGE, "occupied_uids", return_value=set()), mock.patch.object(STAGE, "_command") as command:
                result = STAGE.stage_bundle(base / "bundle.tar.gz", apply=False)
            self.assertFalse(result["apply"])
            self.assertEqual(result["source_sha"], SOURCE_SHA)
            self.assertEqual({role["name"] for role in result["roles"]}, set(STAGE.ROLES))
            command.assert_not_called()
            self.assertNotIn("SECRET", json.dumps(result))

    def test_apply_requires_explicit_root_gate_before_mutation(self):
        with mock.patch.object(STAGE, "verify_bundle", return_value=(SOURCE_SHA, {})), mock.patch.object(STAGE, "host_versions", return_value={}), mock.patch.object(STAGE, "validate_prerequisites"), mock.patch.object(STAGE, "validate_resolver"), mock.patch.object(STAGE, "disk_anchor", return_value=Path("/opt")), mock.patch.object(STAGE.shutil, "disk_usage", return_value=SimpleNamespace(free=STAGE.MIN_FREE_BYTES)), mock.patch.object(STAGE, "validate_accounts"), mock.patch.object(STAGE, "validate_paths"), mock.patch.object(STAGE, "occupied_uids", return_value=set()), mock.patch.object(STAGE.os, "geteuid", return_value=1000):
            with self.assertRaises(STAGE.StageError) as error:
                STAGE.stage_bundle(Path("bundle.tar.gz"), apply=True)
        self.assertEqual(str(error.exception), "apply_requires_root")

    def test_unverified_existing_project_path_is_never_adopted(self):
        with tempfile.TemporaryDirectory() as temp:
            existing = Path(temp) / "existing"
            existing.mkdir()
            with mock.patch.object(STAGE, "NATIVE_ROOT", existing), mock.patch.object(STAGE, "DATA_ROOT", Path(temp) / "data"), mock.patch.object(STAGE, "ACCEPTANCE_ROOT", Path(temp) / "acceptance"), mock.patch.object(STAGE, "CONFIG_ROOT", Path(temp) / "config"), mock.patch.object(STAGE, "RELEASES_ROOT", existing / "releases"):
                with self.assertRaises(STAGE.StageError):
                    STAGE.validate_paths(existing / "releases" / SOURCE_SHA)

    def test_apply_happy_path_updates_state_and_creates_paired_role_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            resolver = base / "stub-resolv.conf"
            resolver.write_text("nameserver 127.0.0.53\n", encoding="ascii")
            native = base / "native"
            releases = native / "releases"
            data = base / "data"
            acceptance = base / "acceptance"
            config = base / "config"
            payload = valid_payload()
            created_groups: set[str] = set()
            commands: list[list[str]] = []
            index = {name: 200 + number for number, name in enumerate(STAGE.ROLES)}

            def command(argv, **_kwargs):
                commands.append(argv)
                if argv[0] == "groupadd":
                    created_groups.add(argv[-1])
                elif argv[:3] == ["python3", "-m", "venv"]:
                    venv = Path(argv[-1])
                    (venv / "bin").mkdir(parents=True)
                    (venv / "bin/python").write_bytes(b"python")
                    (venv / "lib/python3.12/site-packages/jevseo").mkdir(parents=True)
                    (venv / "lib64").symlink_to("lib")
                elif argv[:2] == ["passwd", "--status"]:
                    return f"{argv[2]} L 2026-11-10 0 99999 7 -1\n"
                elif len(argv) > 1 and argv[1] == "-c":
                    release = releases / SOURCE_SHA
                    python = release / "venv/bin/python"
                    package = release / "venv/lib/python3.12/site-packages/jevseo"
                    return json.dumps({"venv_python": str(python), "sys_prefix": str(release / "venv"), "package_dir": str(package), "api_runner": "python -m jevseo.web", "cli_runner": "jevseo"})
                return ""

            def getpwnam(name):
                return SimpleNamespace(pw_uid=index[name], pw_gid=index[name], pw_dir="/nonexistent", pw_shell="/usr/sbin/nologin", pw_passwd="x")

            def getgrnam(name):
                if name not in created_groups:
                    raise KeyError(name)
                return SimpleNamespace(gr_gid=index[name], gr_mem=[])

            def getgrgid(gid):
                return SimpleNamespace(gr_name=next(name for name, value in index.items() if value == gid))

            real_lstat = Path.lstat

            def root_owned_state(path):
                info = real_lstat(path)
                if path.parent == config and (path.name.startswith(".native-stage-state") or path.name == "native-stage-state.json" or path.name == "native-stage-manifest.json"):
                    values = list(info)
                    values[4] = 0
                    return os.stat_result(values)
                if path.name == "lib64" and path.parent.name == "venv":
                    values = list(info)
                    values[4] = 0
                    return os.stat_result(values)
                try:
                    path.relative_to(base)
                except ValueError:
                    return info
                values = list(info)
                values[4] = 0
                return os.stat_result(values)

            patches = {
                "NATIVE_ROOT": native,
                "RELEASES_ROOT": releases,
                "DATA_ROOT": data,
                "ACCEPTANCE_ROOT": acceptance,
                "CONFIG_ROOT": config,
                "RESOLVER_PATH": resolver,
                "DISK_ANCHORS": (base,),
            }
            with mock.patch.multiple(STAGE, **patches), mock.patch.object(STAGE, "verify_bundle", return_value=(SOURCE_SHA, payload)), mock.patch.object(STAGE, "host_versions", return_value={"python": "Python 3.12.3"}), mock.patch.object(STAGE, "validate_prerequisites"), mock.patch.object(STAGE, "validate_paths"), mock.patch.object(STAGE, "disk_anchor", return_value=base), mock.patch.object(STAGE, "validate_accounts"), mock.patch.object(STAGE, "occupied_uids", return_value=set()), mock.patch.object(STAGE, "process_uids", return_value=set()), mock.patch.object(STAGE, "_command", side_effect=command), mock.patch.object(STAGE.pwd, "getpwnam", side_effect=getpwnam), mock.patch.object(STAGE.pwd, "getpwall", return_value=[]), mock.patch.object(STAGE.grp, "getgrnam", side_effect=getgrnam), mock.patch.object(STAGE.grp, "getgrgid", side_effect=getgrgid), mock.patch.object(STAGE.grp, "getgrall", return_value=[]), mock.patch.object(STAGE.os, "getgrouplist", side_effect=lambda _name, gid: [gid]), mock.patch.object(STAGE.os, "geteuid", return_value=0), mock.patch.object(STAGE.os, "chown"), mock.patch.object(Path, "lstat", new=root_owned_state):
                result = STAGE.stage_bundle(base / "bundle.tar.gz", apply=True)
            self.assertEqual([role["gid"] for role in result["roles"]], [role["uid"] for role in result["roles"]])
            self.assertEqual([argv[0] for argv in commands[:9]], ["groupadd", "useradd", "passwd", "groupadd", "useradd", "passwd", "groupadd", "useradd", "passwd"])
            self.assertTrue((releases / SOURCE_SHA / "bin/smokescreen").is_file())
            self.assertTrue((releases / SOURCE_SHA / "smokescreen.json").is_file())
            self.assertEqual(stat.S_IMODE((releases / SOURCE_SHA / "bin/smokescreen").stat().st_mode), 0o755)
            state = json.loads((config / "native-stage-state.json").read_text(encoding="utf-8"))
            self.assertEqual(len(state["created_groups"]), 3)
            self.assertEqual(len(state["created_users"]), 3)
            self.assertTrue(Path(result["manifest"]).is_file())

    def test_account_lock_status_requires_locked_role(self):
        statuses = (
            "jev-audit-api P 2026-11-10 0 99999 7 -1",
            "jev-audit-api N 2026-11-10 0 99999 7 -1",
            "wrong-name L 2026-11-10 0 99999 7 -1",
        )
        entry = SimpleNamespace(pw_uid=321, pw_gid=321, pw_dir="/nonexistent", pw_shell="/usr/sbin/nologin", pw_passwd="x")
        for status in statuses:
            with self.subTest(status=status), mock.patch.object(STAGE, "occupied_uids", return_value=set()), mock.patch.object(STAGE, "process_uids", return_value=set()), mock.patch.object(STAGE.pwd, "getpwall", return_value=[]), mock.patch.object(STAGE.pwd, "getpwnam", return_value=entry), mock.patch.object(STAGE.grp, "getgrall", return_value=[]), mock.patch.object(STAGE.grp, "getgrgid", return_value=SimpleNamespace(gr_name="jev-audit-api")), mock.patch.object(STAGE, "_command", return_value=status):
                with self.assertRaises(STAGE.StageError):
                    STAGE._create_account("jev-audit-api", 321, 321)

    def test_account_rejects_extra_effective_nss_group(self):
        entry = SimpleNamespace(pw_uid=321, pw_gid=321, pw_dir="/nonexistent", pw_shell="/usr/sbin/nologin", pw_passwd="x")
        with mock.patch.object(STAGE, "occupied_uids", return_value=set()), mock.patch.object(STAGE, "process_uids", return_value=set()), mock.patch.object(STAGE.pwd, "getpwall", return_value=[]), mock.patch.object(STAGE.pwd, "getpwnam", return_value=entry), mock.patch.object(STAGE.grp, "getgrall", return_value=[]), mock.patch.object(STAGE.grp, "getgrgid", return_value=SimpleNamespace(gr_name="jev-audit-api")), mock.patch.object(STAGE.os, "getgrouplist", return_value=[321, 654]), mock.patch.object(STAGE, "_command", side_effect=("", "jev-audit-api L 2026-11-10 0 99999 7 -1")):
            with self.assertRaises(STAGE.StageError):
                STAGE._create_account("jev-audit-api", 321, 321)

    def test_venv_allows_only_canonical_lib64_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "venv"
            (root / "lib").mkdir(parents=True)
            (root / "lib64").symlink_to("lib")
            real_lstat = Path.lstat

            def root_owned(path):
                info = real_lstat(path)
                if path == root / "lib64":
                    values = list(info)
                    values[4] = 0
                    return os.stat_result(values)
                return info

            with mock.patch.object(STAGE.os, "chown"), mock.patch.object(Path, "lstat", new=root_owned):
                STAGE._chmod_tree(root)
            os.chmod(root, 0o755)
            (root / "lib64").unlink()
            (root / "lib64").symlink_to("/etc")
            with mock.patch.object(STAGE.os, "chown"):
                with self.assertRaises(STAGE.StageError):
                    STAGE._chmod_tree(root)

    def test_disk_check_uses_existing_allowlisted_ancestor_when_release_root_absent(self):
        safe = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with mock.patch.object(STAGE, "DISK_ANCHORS", (Path("/opt"),)), mock.patch.object(Path, "lstat", return_value=safe):
            self.assertEqual(STAGE.disk_anchor(Path("/opt/jev-audit-native/releases") / SOURCE_SHA), Path("/opt"))
        for unsafe in (
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000),
        ):
            with mock.patch.object(STAGE, "DISK_ANCHORS", (Path("/opt"),)), mock.patch.object(Path, "lstat", return_value=unsafe):
                with self.assertRaisesRegex(STAGE.StageError, "disk_anchor_unsafe"):
                    STAGE.disk_anchor(Path("/opt/jev-audit-native/releases") / SOURCE_SHA)


if __name__ == "__main__":
    unittest.main()
