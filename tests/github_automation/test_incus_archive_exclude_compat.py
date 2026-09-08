from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/host/install-incus-archive-exclude-compat.sh"


class IncusArchiveExcludeCompatTests(unittest.TestCase):
    def test_plan_is_non_mutating_and_apply_is_explicit(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "mode='plan'",
            '"host_changes":false',
            "--apply",
            "--acknowledge-incus-service-mutation",
            '[[ "${acknowledged}" == true ]] || usage',
        ):
            self.assertIn(token, source)
        self.assertLess(source.index("if [[ \"${mode}\" == 'plan' ]]"), source.index("systemctl daemon-reload"))

    def test_apply_is_pinned_inert_and_fail_closed(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "Ubuntu-24.04-CI",
            "6.0.0-1ubuntu0.3",
            "dpkg-query -W -f='${Version}' incus",
            "Incus package does not match the exact compatibility target",
            "self-hosted-ci-garm.service",
            "self-hosted-ci-allocation-broker.service",
            "self-hosted-ci-outbound-worker.service",
            "must be inactive",
            "incus list --all-projects --format csv",
            "Incus contains an instance",
            "Incus instance inventory is unobservable",
            "reserved canary image alias already exists",
            "Incus image alias inventory is unobservable",
            "Incus image fingerprint inventory is unobservable",
        ):
            self.assertIn(token, source)
        self.assertNotIn('[[ -z "$(incus list', source)

    def test_apply_holds_the_canonical_lock_and_requires_zero_runtime(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "/usr/local/lib/self-hosted-ci/garm-jit-transaction-lib.sh",
            'source "${TRANSACTION_LIB}"',
            "acquire_transaction_lock",
            "zero_runtime_state || fail 'GARM scale sets or ci-jit instances remain'",
            "zero_runtime_state || fail 'runtime residue remains after canary cleanup'",
        ):
            self.assertIn(token, source)
        lock = source.index("\nacquire_transaction_lock\n")
        for mutation in (
            'incus list --all-projects --format csv)',
            "systemctl daemon-reload",
            "systemctl restart incus.service",
            'incus image import "${workdir}/nested-dev-canary.tar.gz"',
        ):
            self.assertLess(lock, source.index(mutation))

    def test_inventory_failures_are_not_accepted_as_empty(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(3, source.count('inventory="$(incus list --all-projects --format csv'))
        self.assertIn("cleanup_failed=true", source)
        self.assertIn("Incus instance inventory is unobservable", source)
        self.assertIn(
            "Incus instance inventory is unobservable after canary cleanup", source
        )

    def test_dropin_matches_the_upstream_anchor_and_is_loaded(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "/etc/systemd/system/incus.service.d",
            "ci-jit-archive-excludes.conf",
            "Environment=TAR_OPTIONS=--anchored",
            "managed drop-in metadata drift",
            "managed drop-in content drift",
            "systemctl restart incus.service",
            "property=DropInPaths",
            "property=Environment",
            "TAR_OPTIONS=--anchored",
        ):
            self.assertIn(token, source)
        self.assertIn(
            'dropin_staging="$(mktemp "${DROPIN_DIRECTORY}/.ci-jit-archive-excludes.XXXXXX")"',
            source,
        )
        self.assertNotIn("${DROPIN_PATH}.creating", source)

    def test_canary_exercises_nested_and_root_dev_then_cleans_exactly(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "rootfs/opt/self-hosted-ci/incus-unpack-probe/dev",
            "rootfs/dev",
            "must-remain-excluded",
            "incus image import",
            "incus init",
            "incus file pull",
            "nested dev sentinel content drifted during image initialization",
            "root dev content was not excluded during image initialization",
            'incus delete "${canary_instance}"',
            'incus image alias delete "${canary_image}"',
            'incus image delete "${canary_image_fingerprint}"',
            '"nested_dev_canary_passed":true',
            '"root_dev_exclusion_preserved":true',
        ):
            self.assertIn(token, source)
        self.assertNotIn('file pull "${CANARY_INSTANCE}/dev/forbidden" /dev/null', source)
        self.assertIn("canary_image_fingerprint", source)
        self.assertIn("preexisting_image_inventory", source)
        self.assertIn("canary_import_attempted", source)
        self.assertIn("canary_instance_attempted", source)
        self.assertIn("canary_image_owned", source)
        self.assertIn('sha256sum "${workdir}/nested-dev-canary.tar.gz"', source)
        self.assertIn('"  ci_jit_canary_nonce: ${canary_nonce}"', source)
        self.assertIn("imported canary image fingerprint drifted", source)
        self.assertIn('incus image delete "${canary_image_fingerprint}"', source)

    def test_alias_and_fingerprint_ownership_are_fail_closed(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "alias_target_from_inventory()",
            "fingerprint_state_from_inventory()",
            'incus image alias list --project "${PROJECT}" --format json',
            'incus image list --project "${PROJECT}" --format json',
            "reserved canary image alias already exists",
            "canary image fingerprint ownership is indeterminate",
            'if [[ "${canary_image_owned}" == true ]]',
            'incus image alias delete "${canary_image}"',
            "Incus preexisting image was not preserved",
        ):
            self.assertIn(token, source)
        self.assertNotIn('incus image info "${canary_image}"', source)
        self.assertLess(
            source.index("preexisting_image_inventory=\"$(incus image list"),
            source.index('incus image import "${workdir}/nested-dev-canary.tar.gz"'),
        )
        self.assertLess(
            source.index("canary_import_attempted=true"),
            source.index('incus image import "${workdir}/nested-dev-canary.tar.gz"'),
        )
        self.assertLess(
            source.index("canary_instance_attempted=true"),
            source.index('incus init "${canary_image}" "${canary_instance}"'),
        )
        cleanup = source.split("cleanup() {", 1)[1].split("\n}\ntrap cleanup EXIT", 1)[0]
        self.assertIn('if [[ "${canary_import_attempted}" == true ]]', cleanup)
        self.assertIn('if [[ "${canary_instance_attempted}" == true ]]', cleanup)
        self.assertIn("preexisting_image_inventory", source)

    def test_durable_marker_is_written_only_after_canary_cleanup(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for token in (
            "/etc/self-hosted-ci/incus-archive-exclude-compat.json",
            '"nested_dev_canary_passed":true',
            '"root_dev_exclusion_preserved":true',
            'durable_write "${MARKER_PATH}" "${MARKER_CONTENT}"',
            "0:0:600:1",
        ):
            self.assertIn(token, source)
        final_zero = source.index(
            "zero_runtime_state || fail 'runtime residue remains after canary cleanup'"
        )
        marker_write = source.index(
            'durable_write "${MARKER_PATH}" "${MARKER_CONTENT}"'
        )
        self.assertLess(source.index('incus delete "${canary_instance}"'), final_zero)
        self.assertLess(source.index('incus image delete "${canary_image_fingerprint}"'), final_zero)
        self.assertLess(final_zero, marker_write)

    def test_script_is_valid_bash(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)], text=True, capture_output=True
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
