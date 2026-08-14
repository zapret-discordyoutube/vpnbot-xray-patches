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


if __name__ == "__main__":
    unittest.main()
