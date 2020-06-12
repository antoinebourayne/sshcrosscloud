import os
from unittest import TestCase

from dotenv import dotenv_values, find_dotenv

from sshcrosscloud import utils
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud


class TestSSHCrossCloud(TestCase):
    default_args = {'sshscript': None,
                    'leave': False,
                    'stop': False,
                    'terminate': False,
                    'finish': False,
                    'detach': False,
                    'attach': False,
                    'verbose': False,
                    'status': False,
                    'destroy': False,
                    'norsync': False,
                    'debug': False,
                    'config': False,
                    'v': False,
                    'provider': None,
                    'L': None,
                    'R': None,
                    'i': None}

    # AWS
    def test_wait_until_initialization_aws(self):
        args = self.default_args
        args['v'] = True
        ssh_vars = utils.SSHVar(args)
        ssh_vars.provider = 'aws'
        ssh = SSHCrossCloud(ssh_vars, dotenv_values(find_dotenv()), os.environ)
        ssh.init_provider_specifics()
        ssh.wait_for_public_ip(with_instance=False)
        assert ssh.wait_until_initialization() is None
        ssh.spe_driver.terminate_instance()

    def test_wait_for_public_ip_aws(self):
        self.fail()

    def test_manage_instance_aws(self):
        self.fail()

    def test_attach_to_instance_aws(self):
        self.fail()

    def test_finish_action_aws(self):
        self.fail()

    def test_rsync_to_instance_aws(self):
        self.fail()

    def test_rsync_back_to_local_aws(self):
        self.fail()

    # Azure
    def test_wait_until_initialization_azure(self):
        self.fail()

    def test_wait_for_public_ip_azure(self):
        self.fail()

    def test_manage_instance_azure(self):
        self.fail()

    def test_attach_to_instance_azure(self):
        self.fail()

    def test_finish_action_azure(self):
        self.fail()

    def test_rsync_to_instance_azure(self):
        self.fail()

    def test_rsync_back_to_local_azure(self):
        self.fail()

    # GCP
    def test_wait_until_initialization_gcp(self):
        self.fail()

    def test_wait_for_public_ip_gcp(self):
        self.fail()

    def test_manage_instance_gcp(self):
        self.fail()

    def test_attach_to_instance_gcp(self):
        self.fail()

    def test_finish_action_gcp(self):
        self.fail()

    def test_rsync_to_instance_gcp(self):
        self.fail()

    def test_rsync_back_to_local_gcp(self):
        self.fail()


