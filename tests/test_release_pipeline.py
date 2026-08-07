from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "release_pipeline", ROOT / "scripts" / "release_pipeline.py"
)
assert SPEC and SPEC.loader
release_pipeline = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_pipeline
SPEC.loader.exec_module(release_pipeline)
PROMOTER_SPEC = importlib.util.spec_from_file_location(
    "pilot_and_promote", ROOT / "scripts" / "pilot_and_promote.py"
)
assert PROMOTER_SPEC and PROMOTER_SPEC.loader
pilot_and_promote = importlib.util.module_from_spec(PROMOTER_SPEC)
sys.modules[PROMOTER_SPEC.name] = pilot_and_promote
PROMOTER_SPEC.loader.exec_module(pilot_and_promote)


class ReleasePipelineTests(unittest.TestCase):
    def test_repository_patch_set_is_exact_and_stable(self) -> None:
        rows = release_pipeline.read_patch_rows(ROOT)
        self.assertEqual(len(rows), 3)
        self.assertRegex(release_pipeline.patchset_sha256(rows), r"^[0-9a-f]{64}$")

    def test_manifest_rejects_candidate_that_does_not_belong_to_proven(self) -> None:
        manifest = {
            "schema_version": 1,
            "capability": release_pipeline.CAPABILITY,
            "upstream": {
                "repository": release_pipeline.OFFICIAL_REPOSITORY,
                "tag": "v26.7.28",
                "commit": "a" * 40,
                "commit_time": "2026-07-28T00:00:00Z",
                "source_date_epoch": 1785196800,
            },
            "patch_repository": {"commit": "b" * 40},
            "patches": {
                "set_sha256": "c" * 64,
                "items": [
                    {"name": f"000{index}-patch.patch", "sha256": str(index) * 64}
                    for index in range(1, 4)
                ],
            },
            "release": {
                "candidate_tag": "v26.7.28-vpnbot.8-candidate.1",
                "proven_tag": "v26.7.28-vpnbot.7",
            },
            "toolchain": {"go_version": "1.26"},
            "assets": {
                "Xray-linux-64.zip": {"sha256": "d" * 64, "size": 1},
            },
        }
        with self.assertRaisesRegex(release_pipeline.PipelineError, "does not belong"):
            release_pipeline.validate_manifest(manifest)

    def test_proof_is_bound_to_the_exact_manifest(self) -> None:
        manifest_bytes = b'{"schema_version":1}\n'
        manifest = {"release": {"candidate_tag": "v26.7.28-vpnbot.4-candidate.1"}}
        proof = {
            "schema_version": 1,
            "result": "passed",
            "candidate_tag": "v26.7.28-vpnbot.4-candidate.1",
            "manifest_sha256": release_pipeline.sha256_bytes(manifest_bytes),
            "checks": {"canary": True},
        }
        release_pipeline.validate_proof(proof, manifest, manifest_bytes)
        proof["manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(release_pipeline.PipelineError, "manifest hash"):
            release_pipeline.validate_proof(proof, manifest, manifest_bytes)

    def test_atomic_write_does_not_leave_the_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            path = Path(raw_tmp) / "state.json"
            release_pipeline.write_atomic(path, b"{}\n", mode=0o600)
            self.assertEqual(path.read_bytes(), b"{}\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(path.parent.glob(".*.new")), [])

    def test_legacy_version_statement_maps_to_latest_same_base_proven(self) -> None:
        settings = pilot_and_promote.Settings(
            releases_url="https://forgejo.invalid/releases",
            token_file=Path("/token"),
            canary_node="canary",
            canary_host="127.0.0.1",
            canary_port=10222,
            canary_user="root",
            identity_file=Path("/key"),
            known_hosts_file=Path("/known_hosts"),
            updater_path="/usr/local/bin/vpnbot-xray-core-updater",
            xray_path="/opt/vpnbot/xray-core/bin/xray",
            config_dir="/opt/vpnbot/xray-core/config",
            service_name="vpnbot-xray.service",
            state_dir=Path("/state"),
            canary_script=Path("/canary.py"),
            timeout_seconds=900,
        )
        releases = [
            {"tag_name": "v26.8.1-vpnbot.1", "draft": False, "prerelease": False},
            {"tag_name": "v26.7.28-vpnbot.3", "draft": False, "prerelease": False},
        ]
        statement = (
            "Xray 26.7.28 (Xray, Penetrates Everything.) 0d9b32c (go1.26.4 linux/amd64)\n"
            "VPnBot capability: vpnbot-active-revoke-v3"
        )
        with mock.patch.object(release_pipeline, "list_forgejo_releases", return_value=releases):
            tag = pilot_and_promote.resolve_previous_proven_tag(settings, "token", statement)
        self.assertEqual(tag, "v26.7.28-vpnbot.3")

    def test_remote_version_keeps_capability_lines(self) -> None:
        settings = pilot_and_promote.Settings(
            releases_url="https://forgejo.invalid/releases",
            token_file=Path("/token"),
            canary_node="canary",
            canary_host="127.0.0.1",
            canary_port=10222,
            canary_user="root",
            identity_file=Path("/key"),
            known_hosts_file=Path("/known_hosts"),
            updater_path="/usr/local/bin/vpnbot-xray-core-updater",
            xray_path="/opt/vpnbot/xray-core/bin/xray",
            config_dir="/opt/vpnbot/xray-core/config",
            service_name="vpnbot-xray.service",
            state_dir=Path("/state"),
            canary_script=Path("/canary.py"),
            timeout_seconds=900,
        )
        output = (
            b"Xray 26.7.28 (Xray, Penetrates Everything.) 0d9b32c (go1.26.4 linux/amd64)\n"
            b"VPnBot capability: vpnbot-active-revoke-v3\n"
        )
        completed = __import__("subprocess").CompletedProcess([], 0, output, b"")
        with mock.patch.object(pilot_and_promote, "remote_command", return_value=completed):
            statement, tag = pilot_and_promote.remote_version(settings)
        self.assertEqual(tag, "v26.7.28")
        self.assertIn(release_pipeline.CAPABILITY, statement)


if __name__ == "__main__":
    unittest.main()
