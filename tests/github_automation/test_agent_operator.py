import json
import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from github_automation.agent_operator import (
    AgentOperator,
    AgentOperatorError,
    HostConfig,
    OperatorPaths,
    PrivateOperatorStore,
    REGISTRY_SCHEMA,
    exact_repository,
)


class FakeOperator(AgentOperator):
    def __init__(self, store, host):
        super().__init__(store, host)
        self.authority = {
            "repository": "FacuVCanale/demo",
            "repository_id": 42,
            "installation_id": 9,
            "repository_selection": "selected",
            "default_branch": "main",
            "workflow_path": ".github/workflows/ci-jit-pilot-child.yml",
            "mode": "ci-jit-pilot",
        }
        self.github = {"id": 42, "nameWithOwner": "FacuVCanale/demo", "defaultBranch": "main"}
        self.health = {"eligible": True, "blockers": [], "generated_at": "now", "probe_error": None}
        self.workflow = None
        self.ssh_commands = []

    def _remote_worker_config(self):
        return dict(self.authority)

    def _github_repository(self, repository):
        return dict(self.github)

    def _health(self):
        return dict(self.health)

    def _workflow(self, repository):
        return self.workflow

    def _github_pr(self, repository, pr):
        return {"number": pr, "state": "open", "headSha": "a" * 40, "headRepo": repository}

    def _render_workflow(self):
        return b"name: local\n"

    def _ssh(self, command, *, timeout=45):
        self.ssh_commands.append(command)
        if " status " in command:
            return json.dumps({"approvals": [{
                "request_id": "request-1", "repository": "FacuVCanale/demo",
                "pr_number": 7, "head_sha": "a" * 40, "state": "pending",
            }]})
        return '{"request_id":"request-1","state":"pending","head_sha":"' + "a" * 40 + '"}'


class AgentOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        key = root / "id_ed25519"
        key.write_text("test")
        os.chmod(key, 0o600)
        self.store = PrivateOperatorStore(OperatorPaths(root / "state"))
        self.host = HostConfig(
            "selfhosted-ci-svc@100.117.46.21", key,
            public_sha="d" * 40,
        )
        self.operator = FakeOperator(self.store, self.host)

    def tearDown(self):
        self.temporary.cleanup()

    def test_repository_must_be_exact_and_never_org_wide(self):
        self.assertEqual(exact_repository("FacuVCanale/demo"), "FacuVCanale/demo")
        for value in ("FacuVCanale/*", "FacuVCanale", "*/demo", "owner/repo/extra"):
            with self.subTest(value=value), self.assertRaises(AgentOperatorError):
                exact_repository(value)

    def test_absent_repository_is_github_hosted_by_default(self):
        self.operator.workflow = None
        result = self.operator.status("FacuVCanale/demo")
        self.assertEqual(result["desired_ci_runner"], "github")
        self.assertFalse(result["effective_local"])

    def test_github_default_status_survives_offline_windows_host(self):
        self.operator.workflow = None
        with mock.patch.object(
            self.operator, "_remote_worker_config",
            side_effect=AgentOperatorError("command_unavailable", "offline"),
        ):
            result = self.operator.status("FacuVCanale/demo")
        self.assertEqual(result["desired_ci_runner"], "github")
        self.assertFalse(result["effective_local"])
        self.assertEqual(result["health"]["blockers"], ["host_status_unavailable"])
        self.assertEqual(result["host_error"]["code"], "command_unavailable")

    def test_use_local_plan_is_non_mutating(self):
        with mock.patch("github_automation.agent_operator.run_checked") as command:
            result = self.operator.use_local("FacuVCanale/demo", apply=False)
        self.assertEqual(result["status"], "planned")
        self.assertEqual(result["changes"], ["install:.github/workflows/ci-jit-pilot-child.yml"])
        command.assert_not_called()
        self.assertFalse(self.store.paths.registry.exists())

    def test_use_local_blocks_wrong_selected_repository(self):
        self.operator.authority["repository"] = "FacuVCanale/other"
        result = self.operator.use_local("FacuVCanale/demo", apply=True)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("selected_repository_authority_missing", result["blockers"])
        self.assertFalse(self.store.paths.registry.exists())

    def test_use_local_refuses_to_overwrite_unmanaged_workflow(self):
        self.operator.workflow = {
            "sha": "b" * 40,
            "content": b"user-owned\n",
            "content_sha256": hashlib.sha256(b"user-owned\n").hexdigest(),
        }
        with mock.patch("github_automation.agent_operator.run_checked") as command:
            result = self.operator.use_local("FacuVCanale/demo", apply=True)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("managed_workflow_ownership_unverified", result["blockers"])
        command.assert_not_called()
        self.assertFalse(self.store.paths.registry.exists())

    def test_use_local_installs_exact_workflow_then_commits_private_state(self):
        def mutate(_argv, **_kwargs):
            content = self.operator._render_workflow()
            self.operator.workflow = {
                "sha": "b" * 40,
                "content": content,
                "content_sha256": hashlib.sha256(content).hexdigest(),
            }
            return "{}"
        with mock.patch("github_automation.agent_operator.run_checked", side_effect=mutate) as command:
            result = self.operator.use_local("FacuVCanale/demo", apply=True)
        self.assertEqual(result["status"], "applied")
        argv = command.call_args.args[0]
        self.assertEqual(argv[:4], ["gh", "api", "--method", "PUT"])
        self.assertIn("repos/FacuVCanale/demo/contents/.github/workflows/ci-jit-pilot-child.yml", argv)
        registry = self.store.load()
        self.assertEqual(
            registry["repositories"]["FacuVCanale/demo"]["ci_runner"],
            "local-with-github-fallback",
        )
        self.assertEqual(stat.S_IMODE(self.store.paths.registry.stat().st_mode), 0o600)
        self.assertNotIn("private", self.store.paths.audit.read_text().lower())

    def test_use_local_upgrades_a_previously_owned_workflow(self):
        old_content = b"name: local\n# old pin\n"
        old_digest = hashlib.sha256(old_content).hexdigest()
        self.operator.workflow = {
            "sha": "c" * 40,
            "content": old_content,
            "content_sha256": old_digest,
        }
        with self.store.locked():
            registry = self.store.load()
            registry["repositories"]["FacuVCanale/demo"] = {
                "ci_runner": "local-with-github-fallback",
                "managed_workflow": ".github/workflows/ci-jit-pilot-child.yml",
                "workflow_blob_sha": "c" * 40,
                "workflow_content_sha256": old_digest,
            }
            self.store.save(registry)

        def mutate(_argv, **_kwargs):
            content = self.operator._render_workflow()
            self.operator.workflow = {
                "sha": "d" * 40,
                "content": content,
                "content_sha256": hashlib.sha256(content).hexdigest(),
            }
            return "{}"

        with mock.patch("github_automation.agent_operator.run_checked", side_effect=mutate):
            result = self.operator.use_local("FacuVCanale/demo", apply=True)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(
            self.store.load()["repositories"]["FacuVCanale/demo"]["workflow_blob_sha"],
            "d" * 40,
        )

    def test_run_local_requires_effective_opt_in_and_never_changes_routing(self):
        blocked = self.operator.run_local("FacuVCanale/demo", 7, apply=True)
        self.assertEqual(blocked["status"], "blocked")
        with self.store.locked():
            registry = self.store.load()
            registry["repositories"]["FacuVCanale/demo"] = {
                "ci_runner": "local-with-github-fallback",
                "managed_workflow": ".github/workflows/ci-jit-pilot-child.yml",
                "workflow_blob_sha": "b" * 40,
                "workflow_content_sha256": "c" * 64,
            }
            self.store.save(registry)
        self.operator.workflow = {
            "sha": "b" * 40, "content": b"", "content_sha256": "c" * 64
        }
        applied = self.operator.run_local("FacuVCanale/demo", 7, apply=True)
        self.assertEqual(applied["status"], "approved")
        self.assertFalse(applied["persistent_routing_changed"])
        self.assertIn("--repository FacuVCanale/demo --pr 7", self.operator.ssh_commands[-1])
        self.assertEqual(
            self.store.load()["repositories"]["FacuVCanale/demo"]["ci_runner"],
            "local-with-github-fallback",
        )

    def test_run_local_rejects_fork_head(self):
        content = self.operator._render_workflow()
        digest = hashlib.sha256(content).hexdigest()
        with self.store.locked():
            registry = self.store.load()
            registry["repositories"]["FacuVCanale/demo"] = {
                "ci_runner": "local-with-github-fallback",
                "managed_workflow": ".github/workflows/ci-jit-pilot-child.yml",
                "workflow_blob_sha": "b" * 40,
                "workflow_content_sha256": digest,
            }
            self.store.save(registry)
        self.operator.workflow = {
            "sha": "b" * 40, "content": content, "content_sha256": digest,
        }
        with mock.patch.object(
            self.operator, "_github_pr",
            side_effect=AgentOperatorError("github_pr_unavailable", "fork head"),
        ), self.assertRaisesRegex(AgentOperatorError, "fork head"):
            self.operator.run_local("FacuVCanale/demo", 7, apply=True)

    def test_active_pending_transaction_cannot_be_overwritten(self):
        digest = hashlib.sha256(self.operator._render_workflow()).hexdigest()
        with self.store.locked():
            registry = self.store.load()
            registry["repositories"]["FacuVCanale/demo"] = {
                "ci_runner": "github",
                "pending": {
                    "operation": "use-local", "started_at": "now",
                    "expected_workflow_sha256": digest, "previous_ci_runner": "github",
                },
            }
            self.store.save(registry)
        with mock.patch("github_automation.agent_operator.run_checked") as command:
            with self.assertRaisesRegex(AgentOperatorError, "earlier routing transaction"):
                self.operator.use_local("FacuVCanale/demo", apply=True)
        command.assert_not_called()

    def test_use_github_removes_only_managed_workflow_before_state_change(self):
        self.operator.workflow = {
            "sha": "c" * 40, "content": b"managed", "content_sha256": "d" * 64
        }
        with self.store.locked():
            registry = self.store.load()
            registry["repositories"]["FacuVCanale/demo"] = {
                "ci_runner": "local-with-github-fallback",
                "managed_workflow": ".github/workflows/ci-jit-pilot-child.yml",
                "workflow_blob_sha": "c" * 40,
                "workflow_content_sha256": "d" * 64,
            }
            self.store.save(registry)
        def delete(_argv, **_kwargs):
            self.operator.workflow = None
            return "{}"
        with mock.patch("github_automation.agent_operator.run_checked", side_effect=delete) as command:
            result = self.operator.use_github("FacuVCanale/demo", apply=True)
        self.assertEqual(result["status"], "applied")
        argv = command.call_args.args[0]
        self.assertEqual(argv[:4], ["gh", "api", "--method", "DELETE"])
        self.assertIn("ci-jit-pilot-child.yml", " ".join(argv))
        self.assertEqual(
            self.store.load()["repositories"]["FacuVCanale/demo"]["ci_runner"],
            "github",
        )

    def test_use_github_refuses_unowned_workflow(self):
        self.operator.workflow = {
            "sha": "c" * 40, "content": b"user", "content_sha256": "e" * 64
        }
        result = self.operator.use_github("FacuVCanale/demo", apply=True)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blockers"], ["managed_workflow_ownership_unverified"])

    def test_pending_local_transaction_reconciles_after_external_success(self):
        content = b"name: local\n"
        digest = hashlib.sha256(content).hexdigest()
        self.operator.workflow = {
            "sha": "f" * 40, "content": content, "content_sha256": digest
        }
        with self.store.locked():
            registry = self.store.load()
            registry["repositories"]["FacuVCanale/demo"] = {
                "ci_runner": "github",
                "pending": {
                    "operation": "use-local", "started_at": "now",
                    "expected_workflow_sha256": digest, "previous_ci_runner": "github",
                },
            }
            self.store.save(registry)
        result = self.operator.status("FacuVCanale/demo")
        self.assertTrue(result["pending_reconciled_during_this_status_call"])
        self.assertEqual(result["desired_ci_runner"], "local-with-github-fallback")

    def test_host_config_rejects_shell_metacharacters_and_non_strings(self):
        root = Path(self.temporary.name)
        config = root / "config.json"
        base = {
            "ssh_target": "user@host", "ssh_key": str(self.host.ssh_key),
            "distro": "Ubuntu-24.04-CI", "public_repository": "FacuVCanale/self-hosted-ci",
            "public_sha": "a" * 40,
        }
        for distro in ("Ubuntu;whoami", "Ubuntu && whoami", "Ubuntu $(id)", 7):
            with self.subTest(distro=distro):
                config.write_text(json.dumps({**base, "distro": distro}))
                with self.assertRaises(AgentOperatorError):
                    HostConfig.load(config)

    def test_registry_rejects_group_or_world_permissions(self):
        self.store.paths.root.mkdir(parents=True)
        self.store.paths.registry.write_text(json.dumps({
            "$schema": REGISTRY_SCHEMA,
            "operator_registry_version": 1,
            "repositories": {},
        }))
        os.chmod(self.store.paths.registry, 0o644)
        with self.assertRaisesRegex(AgentOperatorError, "private registry"):
            self.store.load()


if __name__ == "__main__":
    unittest.main()
