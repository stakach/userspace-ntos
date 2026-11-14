"""An idle stop after setup completed and a user logged on is a savable disk milestone."""

import unittest

from scripts.ci_kvm_smoke import post_setup_idle_evidence

SETUP_START = (b"[pm-dynamic] allocated hosted process pi=17 pid=360 parent=96 "
               b"image=setup.exe token=31 inherited\r\n")
SETUP_EXIT = (b"[process-terminal-committed] pi=17 pid=360 generation=12 "
              b"exit-status=0x00000000 signaled=1\r\n")
USER_HIVE = (b"[cm-load] NtLoadKey MOUNTED \\Registry\\User\\S-1-5-21-2098853176-875348418-"
             b"1423597592-1000 <- \\??\\C:\\users\\user\\ntuser.dat bytes=202848\r\n")


class PostSetupIdleEvidenceTests(unittest.TestCase):
    def test_setup_success_followed_by_user_logon_is_evidence(self):
        evidence = post_setup_idle_evidence(SETUP_START + b"noise\r\n" + SETUP_EXIT + USER_HIVE)
        self.assertIn("pid=360", evidence)
        self.assertIn("S-1-5-21-2098853176-875348418-1423597592-1000", evidence)

    def test_setup_exit_alone_is_not_evidence(self):
        # setup.exe also exits 0 on its failure path, before any user can log on.
        self.assertIsNone(post_setup_idle_evidence(SETUP_START + SETUP_EXIT))

    def test_other_process_exit_or_failed_setup_is_not_evidence(self):
        other = SETUP_EXIT.replace(b"pid=360", b"pid=364")
        failed = SETUP_EXIT.replace(b"0x00000000", b"0x00000001")
        for exit_line in (other, failed):
            with self.subTest(exit_line=exit_line):
                self.assertIsNone(post_setup_idle_evidence(SETUP_START + exit_line + USER_HIVE))

    def test_user_hive_before_setup_exit_or_system_hive_is_not_evidence(self):
        self.assertIsNone(post_setup_idle_evidence(SETUP_START + USER_HIVE + SETUP_EXIT))
        system = USER_HIVE.replace(b"S-1-5-21-2098853176-875348418-1423597592-1000", b"S-1-5-18")
        self.assertIsNone(post_setup_idle_evidence(SETUP_START + SETUP_EXIT + system))

    def test_last_setup_instance_decides(self):
        second = SETUP_START.replace(b"pid=360", b"pid=400")
        self.assertIsNone(post_setup_idle_evidence(
            SETUP_START + SETUP_EXIT + USER_HIVE + second))


if __name__ == "__main__":
    unittest.main()
