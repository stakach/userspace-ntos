"""Native executor probe markers are part of each requested boot's acceptance gate."""

import unittest

from scripts.ci_kvm_probe_markers import verify_probe_markers


PASSIVE = b"[executor-passive-worker-probe] PASS"
SUPERVISOR = b"[executor-fault-supervisor-probe] PASS"
PRODUCTION = b"[executor-production-worker] PASS"


class ExecutorProbeMarkerTests(unittest.TestCase):
    def test_unflagged_desktop_boot_has_no_probe_requirement(self):
        self.assertEqual(verify_probe_markers(b"ordinary desktop log\n"), [])

    def test_passive_only_requires_its_checked_bootstrap(self):
        self.assertEqual(verify_probe_markers(PASSIVE + b"\n", require_passive=True), [])
        self.assertIn("passive worker", " ".join(
            verify_probe_markers(b"ordinary desktop log\n", require_passive=True)))

    def test_supervisor_probe_requires_all_three_distinct_workers_in_order(self):
        full = b"\n".join((PASSIVE, SUPERVISOR, PRODUCTION)) + b"\n"
        self.assertEqual(verify_probe_markers(full, require_supervisor=True), [])
        self.assertTrue(verify_probe_markers(
            b"\n".join((PASSIVE, PRODUCTION, SUPERVISOR)) + b"\n",
            require_supervisor=True))
        self.assertTrue(verify_probe_markers(
            b"\n".join((PASSIVE, SUPERVISOR)) + b"\n",
            require_supervisor=True))

    def test_production_refusal_stays_fatal_even_if_pass_appears_later(self):
        log = b"\n".join((PASSIVE, SUPERVISOR,
                          b"[executor-production-worker] FAIL stage=ingress-admission",
                          PRODUCTION)) + b"\n"
        self.assertIn("production worker", " ".join(
            verify_probe_markers(log, require_supervisor=True)))

    def test_passive_or_supervisor_refusal_stays_fatal(self):
        for failing in (b"[executor-passive-worker-probe] FAIL stage=reply",
                        b"[executor-fault-supervisor-probe] FAIL stage=terminal"):
            with self.subTest(failing=failing):
                log = b"\n".join((failing, PASSIVE, SUPERVISOR, PRODUCTION)) + b"\n"
                self.assertTrue(verify_probe_markers(log, require_supervisor=True))


if __name__ == "__main__":
    unittest.main()
