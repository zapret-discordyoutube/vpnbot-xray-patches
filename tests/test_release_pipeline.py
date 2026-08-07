from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "release_pipeline", ROOT / "scripts" / "release_pipeline.py"
)
assert SPEC and SPEC.loader
release_pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_pipeline)


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


if __name__ == "__main__":
    unittest.main()
