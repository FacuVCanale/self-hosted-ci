from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from github_automation.inventory import classify_inventory
from github_automation.policy import evaluate_execution_trust
from github_automation.registry import Registry, RegistryError


SHA = "a" * 64
EXAMPLE_REPOSITORY = "example-owner/example-repo"


def local_entry() -> dict:
    return {
        "ci_runner": "local-with-github-fallback",
        "ai_reviewer": "disabled",
        "execution_trust": {
            "policy_version": 1,
            "mode": "exact-sha-attestation",
            "attestation_authority_version": 1,
            "key_manifest_version": 1,
            "key_manifest_generation": 1,
            "key_manifest_digest": SHA,
            "offline_root_public_fingerprint": SHA,
            "public_key_id": "online-1",
            "public_key_fingerprint": SHA,
            "inventory_drift_guard": "enabled",
        },
        "authority": {
            "kind": "personal-repository",
            "installation_id": 123,
            "runner_group": None,
        },
    }


class RegistryTests(unittest.TestCase):
    def test_absent_repository_is_hosted_and_reviewer_disabled(self) -> None:
        registry = Registry.from_mapping({"registry_schema_version": 1, "repositories": {}})
        resolved = registry.resolve(EXAMPLE_REPOSITORY)
        self.assertEqual("github", resolved.ci_runner)
        self.assertEqual("disabled", resolved.ai_reviewer)
        self.assertFalse(resolved.local_requested)

    def test_exact_local_entry_is_accepted(self) -> None:
        registry = Registry.from_mapping(
            {"registry_schema_version": 1, "repositories": {EXAMPLE_REPOSITORY: local_entry()}}
        )
        self.assertTrue(registry.resolve(EXAMPLE_REPOSITORY).local_requested)

    def test_wildcards_implicit_org_and_unknown_fields_reject(self) -> None:
        invalid = [
            {"registry_schema_version": 1, "repositories": {"example-owner/*": local_entry()}},
            {"registry_schema_version": 1, "repositories": {"example-owner": local_entry()}},
            {"registry_schema_version": 1, "repositories": {}, "allow_all": True},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(RegistryError):
                Registry.from_mapping(value)

    def test_duplicate_json_keys_reject(self) -> None:
        with self.assertRaises(RegistryError):
            Registry.from_json('{"registry_schema_version":1,"registry_schema_version":1,"repositories":{}}')

    def test_enumerated_writers_and_hosted_authority_reject(self) -> None:
        entry = local_entry()
        entry["execution_trust"]["mode"] = "enumerated-writers"
        with self.assertRaises(RegistryError):
            Registry.from_mapping({"registry_schema_version": 1, "repositories": {"o/r": entry}})
        hosted = {"ci_runner": "github", "ai_reviewer": "disabled", "authority": entry["authority"]}
        with self.assertRaises(RegistryError):
            Registry.from_mapping({"registry_schema_version": 1, "repositories": {"o/r": hosted}})

    def test_org_requires_exact_runner_group(self) -> None:
        entry = local_entry()
        entry["authority"] = {
            "kind": "organization-runner-group",
            "installation_id": 456,
            "runner_group": "selected-repository",
        }
        Registry.from_mapping({"registry_schema_version": 1, "repositories": {"org/repo": entry}})
        entry["authority"]["runner_group"] = "*"
        with self.assertRaises(RegistryError):
            Registry.from_mapping({"registry_schema_version": 1, "repositories": {"org/repo": entry}})


class InventoryPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)
        registry = Registry.from_mapping(
            {"registry_schema_version": 1, "repositories": {EXAMPLE_REPOSITORY: local_entry()}}
        )
        self.config = registry.resolve(EXAMPLE_REPOSITORY)

    def observation(self, *, age: timedelta = timedelta(0), records=None):
        return classify_inventory(
            ["collaborators", "rulesets"],
            records if records is not None else {"collaborators": [{"user_id": 1}], "rulesets": []},
            self.now - age,
        )

    def test_inventory_classification_and_hash_exclude_observation_time(self) -> None:
        first = self.observation()
        second = classify_inventory(
            ["rulesets", "collaborators"],
            {"rulesets": [], "collaborators": [{"user_id": 1}]},
            self.now + timedelta(minutes=1),
        )
        self.assertEqual("complete", first.status)
        self.assertEqual(first.semantic_hash, second.semantic_hash)
        partial = self.observation(records={"collaborators": [{"user_id": 1}]})
        self.assertEqual("partial", partial.status)
        self.assertEqual(("rulesets",), partial.missing_source_ids)
        unavailable = self.observation(records={})
        self.assertEqual("unavailable", unavailable.status)

    def test_inventory_change_changes_semantic_hash(self) -> None:
        before = self.observation()
        after = self.observation(records={"collaborators": [{"user_id": 2}], "rulesets": []})
        self.assertNotEqual(before.semantic_hash, after.semantic_hash)

    def test_s74_inventory_never_positively_authorizes(self) -> None:
        decision = evaluate_execution_trust(
            self.config,
            now=self.now,
            inventory=self.observation(),
            attestation_valid=False,
            relationship_signals=("private", "MEMBER", "COLLABORATOR", "same-repository"),
        )
        self.assertEqual("github", decision.backend)
        self.assertFalse(decision.local_eligible)

    def test_only_valid_attestation_and_fresh_guard_enable_local(self) -> None:
        local = evaluate_execution_trust(
            self.config, now=self.now, inventory=self.observation(), attestation_valid=True
        )
        self.assertEqual("local", local.backend)
        self.assertTrue(local.local_eligible)
        for age in (timedelta(minutes=5, seconds=1), timedelta(days=-1)):
            with self.subTest(age=age):
                decision = evaluate_execution_trust(
                    self.config, now=self.now, inventory=self.observation(age=age), attestation_valid=True
                )
                self.assertEqual("github", decision.backend)

    def test_untrusted_events_are_always_hosted(self) -> None:
        for kwargs in ({"dependabot": True}, {"external_contributor": True}):
            with self.subTest(kwargs=kwargs):
                decision = evaluate_execution_trust(
                    self.config,
                    now=self.now,
                    inventory=self.observation(),
                    attestation_valid=True,
                    **kwargs,
                )
                self.assertEqual("github", decision.backend)


if __name__ == "__main__":
    unittest.main()
