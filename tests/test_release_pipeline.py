from __future__ import annotations

import importlib.util
import json
import os
import subprocess
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
ALERT_SPEC = importlib.util.spec_from_file_location(
    "release_alert_monitor", ROOT / "scripts" / "release_alert_monitor.py"
)
assert ALERT_SPEC and ALERT_SPEC.loader
release_alert_monitor = importlib.util.module_from_spec(ALERT_SPEC)
sys.modules[ALERT_SPEC.name] = release_alert_monitor
ALERT_SPEC.loader.exec_module(release_alert_monitor)


class ReleasePipelineTests(unittest.TestCase):
    @staticmethod
    def alert_settings(state_dir: Path) -> release_alert_monitor.Settings:
        return release_alert_monitor.Settings(
            actions_url="https://forgejo.invalid/actions/runs",
            releases_url="https://forgejo.invalid/releases",
            workflow_id="candidate.yml",
            bot_env_file=state_dir / "vpnbot.env",
            chat_id="6483277608",
            promoter_state_dir=state_dir / "promoter",
            state_dir=state_dir / "alerts",
            stall_seconds=7200,
            reminder_seconds=3600,
            retry_seconds=60,
            request_timeout_seconds=20,
        )

    def test_repository_patch_set_is_exact_and_stable(self) -> None:
        rows = release_pipeline.read_patch_rows(ROOT)
        self.assertEqual(len(rows), 3)
        self.assertRegex(release_pipeline.patchset_sha256(rows), r"^[0-9a-f]{64}$")

    def test_http_requests_identify_the_release_robot_with_project_contact(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"ok"
        response.__exit__.return_value = False

        with mock.patch.object(
            release_pipeline.urllib.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            self.assertEqual(
                release_pipeline.request_bytes("https://example.invalid/release"),
                b"ok",
            )

        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.get_header("User-agent"),
            release_pipeline.HTTP_USER_AGENT,
        )
        self.assertIn("https://git.zapret.moe/", release_pipeline.HTTP_USER_AGENT)

    def test_read_request_retries_remote_disconnect_but_write_does_not(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"feed"
        response.__exit__.return_value = False
        with (
            mock.patch.object(
                release_pipeline.urllib.request,
                "urlopen",
                side_effect=[
                    release_pipeline.http.client.RemoteDisconnected(),
                    response,
                ],
            ) as urlopen,
            mock.patch.object(release_pipeline.time, "sleep") as sleep,
        ):
            self.assertEqual(
                release_pipeline.request_bytes("https://example.invalid/feed"),
                b"feed",
            )
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(0.5)

        with mock.patch.object(
            release_pipeline.urllib.request,
            "urlopen",
            side_effect=release_pipeline.http.client.RemoteDisconnected(),
        ) as urlopen:
            with self.assertRaisesRegex(release_pipeline.PipelineError, "request failed"):
                release_pipeline.request_bytes(
                    "https://example.invalid/release",
                    method="POST",
                    payload=b"{}",
                )
        urlopen.assert_called_once()

    def test_create_release_ignores_mutation_response_assets_and_refetches_exact_tag(self) -> None:
        tag = "v26.7.28-vpnbot.9-candidate.1"
        target = "a" * 40
        mutation_response = {
            "id": 77,
            "tag_name": tag,
            "assets": [
                {"name": "unrelated.jpg"},
                {"name": "unrelated.jpg"},
            ],
        }
        canonical = {
            "id": 77,
            "tag_name": tag,
            "target_commitish": target,
            "draft": True,
            "prerelease": True,
            "assets": [],
        }
        with (
            mock.patch.object(
                release_pipeline,
                "request_json",
                return_value=mutation_response,
            ),
            mock.patch.object(
                release_pipeline,
                "release_by_tag",
                return_value=canonical,
            ) as by_tag,
        ):
            created = release_pipeline.create_release(
                "https://forgejo.invalid/releases",
                token="secret",
                tag=tag,
                target=target,
                prerelease=True,
                title="candidate",
                body="body",
            )
        self.assertIs(created, canonical)
        by_tag.assert_called_once_with(
            "https://forgejo.invalid/releases",
            tag,
            token="secret",
        )

    def test_create_release_rejects_refetched_identity_mismatch(self) -> None:
        with (
            mock.patch.object(
                release_pipeline,
                "request_json",
                return_value={"id": 77},
            ),
            mock.patch.object(
                release_pipeline,
                "release_by_tag",
                return_value={
                    "id": 78,
                    "tag_name": "v26.7.28-vpnbot.9-candidate.1",
                    "target_commitish": "a" * 40,
                    "draft": True,
                    "prerelease": True,
                },
            ),
        ):
            with self.assertRaisesRegex(release_pipeline.PipelineError, "changed after creation"):
                release_pipeline.create_release(
                    "https://forgejo.invalid/releases",
                    token="secret",
                    tag="v26.7.28-vpnbot.9-candidate.1",
                    target="a" * 40,
                    prerelease=True,
                    title="candidate",
                    body="body",
                )

    def test_latest_official_release_uses_only_safe_atom_link(self) -> None:
        feed = b"""<?xml version='1.0' encoding='UTF-8'?>
<feed xmlns='http://www.w3.org/2005/Atom'>
  <entry>
    <link rel='alternate' href='https://attacker.invalid/XTLS/Xray-core/releases/tag/v99.1.1'/>
  </entry>
  <entry>
    <link rel='alternate' href='https://github.com/XTLS/Xray-core/releases/tag/v26.7.28'/>
  </entry>
</feed>
"""
        with mock.patch.object(release_pipeline, "request_bytes", return_value=feed) as request:
            self.assertEqual(release_pipeline.latest_official_release(), "v26.7.28")
        request.assert_called_once_with(
            release_pipeline.OFFICIAL_RELEASES_FEED,
            accept="application/atom+xml, application/xml;q=0.9",
        )

    def test_latest_official_release_rejects_invalid_feed(self) -> None:
        with mock.patch.object(release_pipeline, "request_bytes", return_value=b"not xml"):
            with self.assertRaisesRegex(release_pipeline.PipelineError, "invalid XML"):
                release_pipeline.latest_official_release()

    def test_official_git_metadata_comes_from_exact_temporary_tag(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            upstream = Path(raw_tmp) / "upstream"
            upstream.mkdir()
            subprocess.run(["git", "-C", str(upstream), "init", "-q"], check=True)
            (upstream / "go.mod").write_text(
                "module github.com/xtls/xray-core\n\ngo 1.26.4\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", str(upstream), "add", "go.mod"], check=True)
            environment = dict(os.environ)
            environment.update(
                {
                    "GIT_AUTHOR_DATE": "2026-07-28T07:59:48+00:00",
                    "GIT_COMMITTER_DATE": "2026-07-28T07:59:48+00:00",
                }
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(upstream),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "official tag",
                ],
                check=True,
                env=environment,
            )
            subprocess.run(
                ["git", "-C", str(upstream), "tag", "v26.7.28"], check=True
            )
            expected_commit = subprocess.check_output(
                ["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True
            ).strip()

            with mock.patch.object(release_pipeline, "OFFICIAL_REPOSITORY", str(upstream)):
                commit, epoch, commit_time, go_version = (
                    release_pipeline.official_git_metadata("v26.7.28")
                )

        self.assertEqual(commit, expected_commit)
        self.assertEqual(epoch, 1785225588)
        self.assertEqual(commit_time, "2026-07-28T07:59:48Z")
        self.assertEqual(go_version, "1.26.4")

    def test_official_git_failure_is_fail_closed(self) -> None:
        with mock.patch.object(
            release_pipeline.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["git", "fetch"], 180),
        ):
            with self.assertRaisesRegex(release_pipeline.PipelineError, "git init"):
                release_pipeline.official_git_metadata("v26.7.28")

    def test_manifest_rejects_candidate_that_does_not_belong_to_proven(self) -> None:
        assets = {}
        for name, profile in release_pipeline.ARTIFACT_PROFILES.items():
            assets[name] = {
                "sha256": "d" * 64,
                "size": 1,
                **profile,
            }
            assets[f"{name}.dgst"] = {"sha256": "e" * 64, "size": 1}
        manifest = {
            "schema_version": release_pipeline.SCHEMA_VERSION,
            "capability": release_pipeline.CAPABILITY,
            "live_user_audit_capability": (
                release_pipeline.LIVE_USER_AUDIT_CAPABILITY
            ),
            "build_profile": release_pipeline.BUILD_PROFILE,
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
            "assets": assets,
        }
        with self.assertRaisesRegex(release_pipeline.PipelineError, "does not belong"):
            release_pipeline.validate_manifest(manifest)

    def test_build_profile_change_forces_a_new_release_edition(self) -> None:
        manifest = {
            "upstream": {"commit": "a" * 40},
            "patches": {"set_sha256": "b" * 64},
            "capability": release_pipeline.CAPABILITY,
            "build_profile": "legacy-single-amd64",
        }

        self.assertFalse(
            release_pipeline.same_source_and_patches(
                manifest,
                "a" * 40,
                "b" * 64,
            )
        )

    def test_live_user_audit_capability_forces_a_new_release_edition(self) -> None:
        manifest = {
            "upstream": {"commit": "a" * 40},
            "patches": {"set_sha256": "b" * 64},
            "capability": release_pipeline.CAPABILITY,
            "build_profile": release_pipeline.BUILD_PROFILE,
        }

        self.assertFalse(
            release_pipeline.same_source_and_patches(
                manifest,
                "a" * 40,
                "b" * 64,
            )
        )
        manifest["live_user_audit_capability"] = (
            release_pipeline.LIVE_USER_AUDIT_CAPABILITY
        )
        self.assertTrue(
            release_pipeline.same_source_and_patches(
                manifest,
                "a" * 40,
                "b" * 64,
            )
        )

    def test_legacy_manifest_remains_readable_but_cannot_match_new_profile(self) -> None:
        assets = {}
        for name in (
            "Xray-linux-64.zip",
            "Xray-linux-arm64-v8a.zip",
            "Xray-linux-arm32-v7a.zip",
        ):
            assets[name] = {"sha256": "d" * 64, "size": 1}
            assets[f"{name}.dgst"] = {"sha256": "e" * 64, "size": 1}
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
                "candidate_tag": "v26.7.28-vpnbot.4-candidate.1",
                "proven_tag": "v26.7.28-vpnbot.4",
            },
            "toolchain": {"go_version": "1.26.4"},
            "assets": assets,
        }

        release_pipeline.validate_manifest(manifest)
        self.assertFalse(
            release_pipeline.same_source_and_patches(
                manifest, "a" * 40, "c" * 64
            )
        )

    def test_build_script_produces_baseline_and_goamd64_v3(self) -> None:
        source = (ROOT / "scripts" / "build-release.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("build_target Xray-linux-64.zip amd64 \"\" v1", source)
        self.assertIn("build_target Xray-linux-64-v3.zip amd64 \"\" v3", source)
        self.assertIn('go_environment+=("GOAMD64=${goamd64}")', source)

    def test_every_workflow_builds_the_discovered_official_source(self) -> None:
        # ci.yml once tested the patches against the manual upstream.env pin:
        # after the patches moved to v26.9.30 the stale v26.7.28 pin made CI
        # red although the release train itself was healthy.
        for workflow in ("ci.yml", "candidate.yml"):
            with self.subTest(workflow=workflow):
                source = (ROOT / ".forgejo" / "workflows" / workflow).read_text(
                    encoding="utf-8"
                )

                self.assertIn("scripts/release_pipeline.py discover", source)
                self.assertIn(
                    "go-version: ${{ steps.discover.outputs.go_version }}", source
                )
                for script in (
                    "run: scripts/test-patches.sh",
                    "scripts/build-release.sh release-assets",
                ):
                    step = source[: source.index(script)].rsplit("- name:", 1)[1]
                    self.assertIn("VPNBOT_BUILD_ENV_FILE: candidate.env", step)

    def test_build_script_captures_version_before_capability_checks(self) -> None:
        source = (ROOT / "scripts" / "build-release.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'version_statement="$("${package_directory}/xray" version)"',
            source,
        )
        self.assertIn(
            "[[ \"$version_statement\" == *'VPnBot capability: "
            "vpnbot-live-user-audit-v1'* ]]",
            source,
        )
        self.assertNotIn('xray" version \\\n            | grep -Fq', source)

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

    def test_release_alert_uses_only_latest_main_candidate_workflow(self) -> None:
        runs = [
            {
                "id": 20,
                "workflow_id": "candidate.yml",
                "prettyref": "main",
                "status": "failure",
                "title": "new Xray",
                "html_url": "https://forgejo.invalid/actions/runs/20",
            },
            {
                "id": 19,
                "workflow_id": "candidate.yml",
                "prettyref": "main",
                "status": "success",
            },
            {
                "id": 99,
                "workflow_id": "ci.yml",
                "prettyref": "main",
                "status": "failure",
            },
        ]
        condition = release_alert_monitor.evaluate_patch_pipeline(runs, "candidate.yml")
        self.assertEqual(condition.status, "problem")
        self.assertEqual(condition.signature, "run:20:failure")

        runs[0]["status"] = "running"
        self.assertEqual(
            release_alert_monitor.evaluate_patch_pipeline(runs, "candidate.yml").status,
            "pending",
        )
        runs[0]["status"] = "success"
        self.assertEqual(
            release_alert_monitor.evaluate_patch_pipeline(runs, "candidate.yml").status,
            "healthy",
        )

    def test_release_alert_reads_structured_public_run_when_api_is_empty(self) -> None:
        listing = """
        <div class="flex-item tw-items-center">
          <div><a href="/zapretkvn/vpnbot-xray-patches/actions/runs/25">run</a></div>
          <b>#25</b>
          <a class="ui label run-list-ref gt-ellipsis" data-tooltip-content="main">main</a>
          <relative-time datetime="2026-08-09T09:17:31+03:00"></relative-time>
        </div>
        """
        state = {
            "state": {
                "run": {
                    "status": "waiting",
                    "title": "Follow official Xray dev releases",
                    "commit": {"branch": {"name": "main"}},
                }
            }
        }
        detail = (
            '<div data-initial-post-response="'
            + __import__("html").escape(json.dumps(state), quote=True)
            + '"></div>'
        )
        with mock.patch.object(
            release_alert_monitor,
            "fetch_text",
            side_effect=(listing, detail),
        ):
            runs = release_alert_monitor.fetch_actions_html(
                "https://git.zapret.moe/api/v1/repos/"
                "zapretkvn/vpnbot-xray-patches/actions/runs",
                "candidate.yml",
                20,
            )

        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["id"], 25)
        self.assertEqual(runs[0]["status"], "waiting")
        self.assertEqual(runs[0]["prettyref"], "main")

    def test_release_alert_escalates_a_stalled_pending_workflow(self) -> None:
        condition = release_alert_monitor.evaluate_patch_pipeline(
            [
                {
                    "id": 25,
                    "workflow_id": "candidate.yml",
                    "prettyref": "main",
                    "status": "waiting",
                    "title": "scheduled",
                    "created_at": "2026-08-09T06:00:00Z",
                    "html_url": "https://forgejo.invalid/actions/runs/25",
                }
            ],
            "candidate.yml",
            now_epoch=int(
                __import__("datetime").datetime(
                    2026,
                    8,
                    9,
                    9,
                    0,
                    tzinfo=__import__("datetime").timezone.utc,
                ).timestamp()
            ),
            stall_seconds=7200,
        )

        self.assertEqual(condition.status, "problem")
        self.assertEqual(condition.signature, "run:25:stalled:waiting")
        self.assertIn("runner", condition.action)

    def test_candidate_stall_is_bound_to_publication_time(self) -> None:
        candidate = release_alert_monitor.Candidate(
            tag="v26.8.1-vpnbot.1-candidate.1",
            proven_tag="v26.8.1-vpnbot.1",
            published_epoch=1_000,
            release_url="https://forgejo.invalid/candidate",
        )
        before = release_alert_monitor.evaluate_candidate_stall([candidate], 8_199, 7_200)
        stalled = release_alert_monitor.evaluate_candidate_stall([candidate], 8_200, 7_200)
        self.assertEqual(before.status, "healthy")
        self.assertEqual(stalled.status, "problem")
        self.assertIn(candidate.tag, stalled.detail)

    def test_canary_failure_distinguishes_failed_rollback_and_retry(self) -> None:
        candidate = release_alert_monitor.Candidate(
            tag="v26.8.1-vpnbot.1-candidate.1",
            proven_tag="v26.8.1-vpnbot.1",
            published_epoch=1_000,
            release_url="https://forgejo.invalid/candidate",
        )
        failed_state = {
            "phase": "failed_rollback_failed",
            "failed_at": "2026-08-07T00:00:00Z",
            "error": "pilot failed; rollback failed",
        }
        failed = release_alert_monitor.evaluate_canary(
            [candidate], {candidate.tag: failed_state}
        )
        self.assertEqual(failed.status, "problem")
        self.assertEqual(failed.severity, "critical")
        self.assertIn("ОТКАТ ТОЖЕ НЕ УДАЛСЯ", failed.detail)

        retrying = dict(failed_state, phase="installing")
        self.assertEqual(
            release_alert_monitor.evaluate_canary(
                [candidate], {candidate.tag: retrying}
            ).status,
            "pending",
        )

    def test_alert_state_deduplicates_pending_and_sends_one_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            settings = self.alert_settings(Path(raw_tmp))
            sent: list[str] = []

            def sender(text: str) -> int:
                sent.append(text)
                return len(sent) + 100

            problem = release_alert_monitor.Condition(
                name="canary_failed",
                status="problem",
                signature="candidate:failed",
                headline="Canary failed",
                detail="diagnostic",
                action="inspect",
            )
            release_alert_monitor.reconcile(settings, [problem], sender, 1_000)
            release_alert_monitor.reconcile(settings, [problem], sender, 1_100)
            release_alert_monitor.reconcile(
                settings,
                [release_alert_monitor.Condition(name="canary_failed", status="pending")],
                sender,
                1_200,
            )
            self.assertEqual(len(sent), 1)

            healthy = release_alert_monitor.Condition(
                name="canary_failed", status="healthy"
            )
            release_alert_monitor.reconcile(settings, [healthy], sender, 1_300)
            release_alert_monitor.reconcile(settings, [healthy], sender, 1_400)
            self.assertEqual(len(sent), 2)
            self.assertIn("состояние выпуска восстановлено", sent[-1])

    def test_failed_delivery_waits_before_retry(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            settings = self.alert_settings(Path(raw_tmp))
            attempts = 0

            def failing_sender(_text: str) -> int:
                nonlocal attempts
                attempts += 1
                raise release_pipeline.PipelineError("delivery failed")

            problem = release_alert_monitor.Condition(
                name="patch_pipeline",
                status="problem",
                signature="run:42:failure",
                headline="Workflow failed",
                detail="diagnostic",
                action="inspect",
            )
            with self.assertRaisesRegex(release_pipeline.PipelineError, "delivery failed"):
                release_alert_monitor.reconcile(settings, [problem], failing_sender, 1_000)
            release_alert_monitor.reconcile(settings, [problem], failing_sender, 1_030)
            self.assertEqual(attempts, 1)

    def test_published_proven_removes_candidate_from_monitoring(self) -> None:
        candidate_release = {
            "tag_name": "v26.8.1-vpnbot.1-candidate.1",
            "draft": False,
            "prerelease": True,
            "published_at": "2026-08-07T10:00:00Z",
            "html_url": "https://forgejo.invalid/candidate",
        }
        proven_release = {
            "tag_name": "v26.8.1-vpnbot.1",
            "draft": False,
            "prerelease": False,
        }
        manifest = {
            "release": {
                "candidate_tag": candidate_release["tag_name"],
                "proven_tag": proven_release["tag_name"],
            }
        }
        with mock.patch.object(
            release_pipeline, "read_release_manifest", return_value=manifest
        ):
            candidates = release_alert_monitor.unproven_candidates(
                [candidate_release, proven_release]
            )
        self.assertEqual(candidates, [])

    def test_direct_monitor_loads_only_known_root_only_environment(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            env_path = Path(raw_tmp) / "release-alert.env"
            env_path.write_text(
                "VPNBOT_XRAY_ALERT_CHAT_ID=6483277608\n"
                "VPNBOT_XRAY_ALERT_STALL_SECONDS='7200'\n",
                encoding="utf-8",
            )
            env_path.chmod(0o600)
            with mock.patch.dict(
                os.environ,
                {
                    "VPNBOT_XRAY_ALERT_CHAT_ID": "",
                    "VPNBOT_XRAY_ALERT_STALL_SECONDS": "",
                },
                clear=False,
            ):
                os.environ.pop("VPNBOT_XRAY_ALERT_CHAT_ID")
                os.environ.pop("VPNBOT_XRAY_ALERT_STALL_SECONDS")
                release_alert_monitor.load_alert_environment(env_path)
                self.assertEqual(
                    os.environ["VPNBOT_XRAY_ALERT_CHAT_ID"], "6483277608"
                )
                self.assertEqual(
                    os.environ["VPNBOT_XRAY_ALERT_STALL_SECONDS"], "7200"
                )

    def test_monitor_lock_is_root_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            lock_path = Path(raw_tmp) / "monitor.lock"
            with release_alert_monitor.monitor_lock(lock_path) as lock:
                self.assertFalse(lock.closed)
                self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)



TOKEN = "123456789:" + "A" * 35


class PatchCiWatchTests(unittest.TestCase):
    """ci.yml red since 01.10.2026 went unnoticed: only candidate.yml was watched."""

    @staticmethod
    def workflow_run(run_id: int, workflow: str, status: str) -> dict[str, object]:
        return {
            "id": run_id,
            "workflow_id": workflow,
            "prettyref": "main",
            "status": status,
            "title": "Patch",
            "html_url": f"https://forgejo.invalid/runs/{run_id}",
            "created_at": "2026-10-03T00:00:00Z",
        }

    def test_red_ci_is_its_own_problem_while_candidate_is_green(self) -> None:
        runs = [self.workflow_run(5384, "candidate.yml", "success"), self.workflow_run(5385, "ci.yml", "failure")]
        candidate = release_alert_monitor.evaluate_patch_pipeline(runs, "candidate.yml")
        ci = release_alert_monitor.evaluate_patch_pipeline(
            runs, "ci.yml", watch=release_alert_monitor.PATCH_CI_WATCH
        )
        self.assertEqual((candidate.name, candidate.status), ("patch_pipeline", "healthy"))
        self.assertEqual((ci.name, ci.status), ("patch_ci", "problem"))
        self.assertEqual(ci.signature, "run:5385:failure")
        self.assertIn("XTLS", ci.detail)

    def test_green_ci_recovers(self) -> None:
        runs = [self.workflow_run(5385, "ci.yml", "failure"), self.workflow_run(5390, "ci.yml", "success")]
        ci = release_alert_monitor.evaluate_patch_pipeline(
            runs, "ci.yml", watch=release_alert_monitor.PATCH_CI_WATCH
        )
        self.assertEqual(ci.status, "healthy")
        self.assertIn("снова зелёная", release_alert_monitor.recovery_text("patch_ci", {}))

    def test_collect_conditions_watches_both_workflows(self) -> None:
        runs = [self.workflow_run(5384, "candidate.yml", "success"), self.workflow_run(5385, "ci.yml", "failure")]
        with tempfile.TemporaryDirectory() as raw_tmp:
            settings = ReleasePipelineTests.alert_settings(Path(raw_tmp))
            (Path(raw_tmp) / "promoter").mkdir()
            with (
                mock.patch.object(release_alert_monitor, "fetch_actions", return_value=runs) as fetch,
                mock.patch.object(release_pipeline, "list_forgejo_releases", return_value=[]),
            ):
                conditions = release_alert_monitor.collect_conditions(settings, 1_790_000_000)
        self.assertEqual(
            [call.args[2] for call in fetch.call_args_list], ["candidate.yml", "ci.yml"]
        )
        by_name = {condition.name: condition.status for condition in conditions}
        self.assertEqual(by_name["patch_ci"], "problem")
        self.assertEqual(by_name["patch_pipeline"], "healthy")


class SourceUnavailabilityTests(unittest.TestCase):
    """Forgejo stops ~90 s nightly for its backup; that is not a release verdict."""

    @staticmethod
    def http_error(code: int) -> Exception:
        return release_pipeline.urllib.error.HTTPError(
            "https://forgejo.invalid/x", code, "status", {}, None
        )

    def test_server_errors_and_rate_limit_are_typed_source_unavailability(self) -> None:
        for status, code in (
            (502, release_pipeline.SOURCE_SERVER_ERROR),
            (503, release_pipeline.SOURCE_SERVER_ERROR),
            (429, release_pipeline.SOURCE_RATE_LIMITED),
        ):
            with (
                mock.patch.object(
                    release_pipeline.urllib.request, "urlopen", side_effect=self.http_error(status)
                ),
                self.assertRaises(release_pipeline.SourceUnavailableError) as raised,
            ):
                release_pipeline.request_bytes("https://forgejo.invalid/x")
            self.assertEqual(raised.exception.code, code)

    def test_client_error_stays_a_contract_failure(self) -> None:
        error = self.http_error(404)
        error.read = lambda _size=-1: b"not found"
        with (
            mock.patch.object(release_pipeline.urllib.request, "urlopen", side_effect=error),
            self.assertRaises(release_pipeline.PipelineError) as raised,
        ):
            release_pipeline.request_bytes("https://forgejo.invalid/x")
        self.assertNotIsInstance(raised.exception, release_pipeline.SourceUnavailableError)

    def test_exhausted_transport_retries_are_unreachable(self) -> None:
        with (
            mock.patch.object(
                release_pipeline.urllib.request,
                "urlopen",
                side_effect=release_pipeline.urllib.error.URLError("refused"),
            ),
            mock.patch.object(release_pipeline.time, "sleep"),
            self.assertRaises(release_pipeline.SourceUnavailableError) as raised,
        ):
            release_pipeline.request_bytes("https://forgejo.invalid/x")
        self.assertEqual(raised.exception.code, release_pipeline.SOURCE_UNREACHABLE)

    def test_observe_judges_nothing_while_the_source_is_absent(self) -> None:
        error = release_pipeline.SourceUnavailableError(
            release_pipeline.SOURCE_SERVER_ERROR, "HTTP 502"
        )
        with mock.patch.object(release_alert_monitor, "collect_conditions", side_effect=error):
            observation = release_alert_monitor.observe(mock.sentinel.settings, 1_000)
        self.assertEqual(observation.conditions, [])
        self.assertIs(observation.source_error, error)

    def test_planned_stop_is_silent_and_a_long_outage_alerts_once_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            settings = ReleasePipelineTests.alert_settings(Path(raw_tmp))
            sent: list[str] = []

            def sender(text: str) -> int:
                sent.append(text)
                return len(sent)

            error = release_pipeline.SourceUnavailableError(
                release_pipeline.SOURCE_SERVER_ERROR, "HTTP 502 for https://forgejo.invalid/x"
            )
            reconcile = release_alert_monitor.reconcile
            # 2026-09-28 03:26: one 502 inside the ~90 s backup stop.
            reconcile(settings, [], sender, 10_000, error)
            reconcile(settings, [], sender, 10_090)
            self.assertEqual(sent, [])

            start = 20_000
            for offset in range(0, 1_800 + 1, 300):
                reconcile(settings, [], sender, start + offset, error)
            self.assertEqual(len(sent), 1)
            self.assertIn("не может прочитать Forgejo", sent[0])
            self.assertIn(release_pipeline.SOURCE_SERVER_ERROR, sent[0])
            reconcile(settings, [], sender, start + 2_400, error)
            self.assertEqual(len(sent), 1)

            reconcile(settings, [], sender, start + 3_000)
            self.assertEqual(len(sent), 2)
            self.assertIn("Forgejo снова отвечает", sent[1])
            state = json.loads((settings.state_dir / "state.json").read_text())
            self.assertNotIn("unavailable_since_epoch", state["conditions"]["release_source"])

    def test_outage_neither_resolves_nor_reopens_other_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            settings = ReleasePipelineTests.alert_settings(Path(raw_tmp))
            sent: list[str] = []
            problem = release_alert_monitor.Condition(
                name="canary_failed",
                status="problem",
                signature="candidate:failed",
                headline="Canary failed",
                detail="diagnostic",
                action="inspect",
            )
            release_alert_monitor.reconcile(settings, [problem], sent.append, 1_000)
            error = release_pipeline.SourceUnavailableError(
                release_pipeline.SOURCE_UNREACHABLE, "request failed"
            )
            release_alert_monitor.reconcile(settings, [], sent.append, 2_000, error)
            state = json.loads((settings.state_dir / "state.json").read_text())
            self.assertTrue(state["conditions"]["canary_failed"]["active"])
            self.assertEqual(len(sent), 1)

    def test_state_written_by_the_previous_release_still_loads(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            path = Path(raw_tmp) / "state.json"
            path.write_text(json.dumps({
                "schema_version": 1,
                "conditions": {"patch_pipeline": {"active": False}},
            }))
            os.chmod(path, 0o600)
            self.assertIn("patch_pipeline", release_alert_monitor.load_state(path)["conditions"])

    def test_promoter_defers_when_the_source_is_absent_before_any_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            settings = mock.Mock(state_dir=Path(raw_tmp) / "promoter", token_file=Path(raw_tmp))
            error = release_pipeline.SourceUnavailableError(
                release_pipeline.SOURCE_SERVER_ERROR, "HTTP 502"
            )
            with (
                mock.patch.object(pilot_and_promote, "load_settings", return_value=settings),
                mock.patch.object(pilot_and_promote, "load_token", return_value="token"),
                mock.patch.object(pilot_and_promote, "select_candidate", side_effect=error),
                mock.patch.object(pilot_and_promote, "process_candidate") as process,
            ):
                self.assertEqual(pilot_and_promote.main(), 0)
            process.assert_not_called()


class TelegramDeliveryContractTests(unittest.TestCase):
    """Plain HTTPS to api.telegram.org: the host's Telegram front owns the path."""

    @staticmethod
    def write_env(directory: Path, text: str) -> Path:
        path = directory / "vpnbot.env"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return path

    def assert_code(self, raised: unittest.case._AssertRaisesContext, code: str) -> None:  # type: ignore[name-defined]
        self.assertEqual(raised.exception.code, code)
        self.assertNotIn(TOKEN, str(raised.exception))

    def sender(self, raw_tmp: str, post: object) -> object:
        return release_alert_monitor.telegram_sender(
            ReleasePipelineTests.alert_settings(Path(raw_tmp)),
            release_alert_monitor.BotRuntime(token=TOKEN),
            post=post,  # type: ignore[arg-type]
            tls_context_factory=lambda: None,  # type: ignore[arg-type,return-value]
        )

    def test_runtime_reads_only_the_token_and_ignores_retired_policy_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            path = self.write_env(
                Path(raw_tmp),
                f"VPNBOT_BOT_TOKEN={TOKEN}\n"
                "VPNBOT_TELEGRAM_IP_FAMILY=garbage\n"
                "VPNBOT_TELEGRAM_API_FALLBACK_IPV4S=not-an-ip\n",
            )
            self.assertEqual(
                release_alert_monitor.load_bot_runtime(path),
                release_alert_monitor.BotRuntime(token=TOKEN),
            )

    def test_runtime_refuses_a_duplicated_token(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            path = self.write_env(Path(raw_tmp), f"VPNBOT_BOT_TOKEN={TOKEN}\nVPNBOT_BOT_TOKEN={TOKEN}\n")
            with self.assertRaisesRegex(release_pipeline.PipelineError, "duplicate"):
                release_alert_monitor.load_bot_runtime(path)

    def test_post_connects_to_api_telegram_org_with_the_given_tls_context(self) -> None:
        connection = mock.Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b"{}"
        factory = mock.Mock(return_value=connection)
        context = object()
        answer = release_alert_monitor.post_telegram(
            "/botX/sendMessage", b"{}", timeout=7, tls_context=context, connection_factory=factory
        )
        self.assertEqual(answer, (200, b"{}"))
        factory.assert_called_once_with("api.telegram.org", 443, timeout=7, context=context)
        connection.close.assert_called_once()

    def test_connect_failure_sends_nothing_and_send_failure_is_ambiguous(self) -> None:
        refused = mock.Mock()
        refused.connect.side_effect = ConnectionRefusedError()
        self.assertIsNone(
            release_alert_monitor.post_telegram(
                "/botX/sendMessage", b"{}", timeout=7, tls_context=None,  # type: ignore[arg-type]
                connection_factory=lambda *_a, **_k: refused,
            )
        )
        refused.request.assert_not_called()
        silent = mock.Mock()
        silent.getresponse.side_effect = TimeoutError()
        with self.assertRaises(release_alert_monitor.TelegramDeliveryError) as raised:
            release_alert_monitor.post_telegram(
                "/botX/sendMessage", b"{}", timeout=7, tls_context=None,  # type: ignore[arg-type]
                connection_factory=lambda *_a, **_k: silent,
            )
        self.assert_code(raised, release_alert_monitor.TELEGRAM_DELIVERY_AMBIGUOUS)

    def test_sender_posts_once_and_returns_the_message_id(self) -> None:
        posted: list[str] = []

        def post(path: str, payload: bytes, **_kwargs: object) -> object:
            posted.append(path)
            self.assertEqual(json.loads(payload)["chat_id"], "6483277608")
            return 200, b'{"ok": true, "result": {"message_id": 77}}'

        with tempfile.TemporaryDirectory() as raw_tmp:
            self.assertEqual(self.sender(raw_tmp, post)("hello"), 77)  # type: ignore[operator]
        self.assertEqual(posted, [f"/bot{TOKEN}/sendMessage"])

    def test_sender_types_every_failure_without_leaking_the_token(self) -> None:
        cases = (
            (None, release_alert_monitor.TELEGRAM_CONNECT_FAILED),
            ((403, b'{"ok": false}'), release_alert_monitor.TELEGRAM_HTTP_STATUS),
            ((200, b"not json"), release_alert_monitor.TELEGRAM_RESPONSE_INVALID),
            ((200, b'{"ok": false, "result": {"message_id": 1}}'), release_alert_monitor.TELEGRAM_REJECTED),
        )
        for answer, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as raw_tmp:
                send = self.sender(raw_tmp, lambda *_a, _answer=answer, **_k: _answer)
                with self.assertRaises(release_alert_monitor.TelegramDeliveryError) as raised:
                    send("hello")  # type: ignore[operator]
                self.assert_code(raised, code)

    def test_monitor_keeps_no_routing_of_its_own(self) -> None:
        source = (ROOT / "scripts" / "release_alert_monitor.py").read_text(encoding="utf-8")
        for retired in (
            "VPNBOT_TELEGRAM_IP_FAMILY",
            "VPNBOT_TELEGRAM_API_FALLBACK_IPV4S",
            "telegram-egress.json",
            "TelegramRoute",
        ):
            self.assertNotIn(retired, source)


class CanaryJumpTests(unittest.TestCase):
    """27.09.2026: the host's direct route to the canary timed out while the hub
    reached it through a bridge; the promoter can take the same jump."""

    def _settings(self, **jump: object) -> "pilot_and_promote.Settings":
        return pilot_and_promote.Settings(
            releases_url="https://forgejo.invalid/releases",
            token_file=Path("/token"),
            canary_node="canary",
            canary_host="203.0.113.5",
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
            **jump,
        )

    def test_without_a_jump_the_command_is_unchanged(self) -> None:
        command = pilot_and_promote.ssh_base(self._settings())
        self.assertFalse(any("ProxyCommand" in part for part in command))
        self.assertEqual("root@203.0.113.5", command[-1])

    def test_a_jump_goes_through_the_bridge_with_pinned_hosts(self) -> None:
        command = pilot_and_promote.ssh_base(
            self._settings(
                jump_host="198.51.100.7",
                jump_port=10222,
                jump_user="vpnbot-bridge",
                jump_identity_file=Path("/bridge_key"),
            )
        )
        self.assertEqual("root@203.0.113.5", command[-1])
        proxy = [part for part in command if part.startswith("ProxyCommand=")]
        self.assertEqual(
            [
                "ProxyCommand=ssh -W %h:%p -p 10222 -i /bridge_key -o BatchMode=yes "
                "-o IdentitiesOnly=yes -o StrictHostKeyChecking=yes "
                "-o UserKnownHostsFile=/known_hosts -o ConnectTimeout=15 "
                "vpnbot-bridge@198.51.100.7"
            ],
            proxy,
        )
        self.assertIn("StrictHostKeyChecking=yes", command)

    def test_a_partial_jump_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name in ("token", "key", "known_hosts", "canary.py"):
                (root / name).write_text("x\n", encoding="utf-8")
            os.chmod(root / "token", 0o600)
            env = {
                "VPNBOT_XRAY_FORGEJO_TOKEN_FILE": str(root / "token"),
                "VPNBOT_XRAY_CANARY_NODE": "canary",
                "VPNBOT_XRAY_CANARY_HOST": "203.0.113.5",
                "VPNBOT_XRAY_CANARY_IDENTITY_FILE": str(root / "key"),
                "VPNBOT_XRAY_CANARY_KNOWN_HOSTS_FILE": str(root / "known_hosts"),
                "VPNBOT_XRAY_CANARY_SCRIPT": str(root / "canary.py"),
                "VPNBOT_XRAY_CANARY_JUMP_HOST": "198.51.100.7",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(release_pipeline.PipelineError) as refused:
                    pilot_and_promote.load_settings()
            self.assertIn("jump", str(refused.exception))
            env.update(
                {
                    "VPNBOT_XRAY_CANARY_JUMP_PORT": "10222",
                    "VPNBOT_XRAY_CANARY_JUMP_USER": "vpnbot-bridge",
                    "VPNBOT_XRAY_CANARY_JUMP_IDENTITY_FILE": str(root / "key"),
                }
            )
            with mock.patch.dict(os.environ, env, clear=True):
                settings = pilot_and_promote.load_settings()
            self.assertEqual("vpnbot-bridge", settings.jump_user)
            # A known_hosts path the shell would interpret is refused for a jump.
            odd = root / "known hosts;x"
            odd.write_text("x\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ, {**env, "VPNBOT_XRAY_CANARY_KNOWN_HOSTS_FILE": str(odd)}, clear=True
            ):
                with self.assertRaises(release_pipeline.PipelineError):
                    pilot_and_promote.load_settings()
            with mock.patch.dict(
                os.environ, {**env, "VPNBOT_XRAY_CANARY_JUMP_PORT": "ssh"}, clear=True
            ):
                with self.assertRaises(release_pipeline.PipelineError):
                    pilot_and_promote.load_settings()


if __name__ == "__main__":
    unittest.main()
