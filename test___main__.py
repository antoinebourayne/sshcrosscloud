import os
from unittest import TestCase

from sshcrosscloud.__main__ import SSHCrossCloud, create_instance, terminate_instance


class Test(TestCase):
    def test_create_instance(self):
        os.environ['PROVIDER'] = 'AWS'
        ssh = SSHCrossCloud()
        assert create_instance(ssh) == 0
        terminate_instance(ssh)
        self.fail()