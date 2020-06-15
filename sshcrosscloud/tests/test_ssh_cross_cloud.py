import logging
import os
from unittest import TestCase

import coloredlogs
from dotenv import dotenv_values, find_dotenv

from sshcrosscloud import utils
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud


class TestSSHCrossCloud(TestCase):
    default_args = utils.default_args

    def get_testing_ssh(self, provider: str) -> SSHCrossCloud:
        args = self.default_args
        logging.getLogger().setLevel(logging.INFO)
        coloredlogs.install(level='INFO')
        ssh_vars = utils.SSHVar(args)
        ssh_vars.provider = provider
        ssh = SSHCrossCloud(ssh_vars, dotenv_values(find_dotenv()), os.environ)
        ssh.init_provider_specifics()
        return ssh

    # AWS
    def test_wait_until_initialization_aws(self):
        ssh = self.get_testing_ssh('aws')
        ssh.init_instance(with_instance=False)
        assert ssh.wait_until_initialization() is None
        ssh.spe_driver.terminate_instance()

    def test_init_instance_aws(self):
        ssh = self.get_testing_ssh('aws')
        assert ssh.init_instance(with_instance=False) is None
        assert ssh.init_instance(with_instance=True) is None
        ssh.wait_until_initialization()
        ssh.spe_driver.terminate_instance()

    def test_manage_instance_aws(self):
        ssh = self.get_testing_ssh('aws')
        assert ssh.manage_instance() is None
        assert ssh.manage_instance() is None
        ssh.wait_until_initialization()
        ssh.spe_driver.terminate_instance()

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
        ssh = self.get_testing_ssh('azure')
        ssh.init_instance(with_instance=False)
        assert ssh.wait_until_initialization() is None
        ssh.spe_driver.terminate_instance()

    def test_init_instance_azure(self):
        ssh = self.get_testing_ssh('azure')
        assert ssh.init_instance(with_instance=False) is None
        assert ssh.init_instance(with_instance=True) is None
        ssh.wait_until_initialization()
        ssh.spe_driver.terminate_instance()

    def test_manage_instance_azure(self):
        ssh = self.get_testing_ssh('azure')
        assert ssh.init_instance(with_instance=False) is None
        assert ssh.init_instance(with_instance=True) is None
        ssh.wait_until_initialization()
        ssh.spe_driver.terminate_instance()

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
        ssh = self.get_testing_ssh('gcp')
        ssh.init_instance(with_instance=False)
        assert ssh.wait_until_initialization() is None
        ssh.spe_driver.terminate_instance()

    def test_init_instance_gcp(self):
        ssh = self.get_testing_ssh('gcp')
        assert ssh.init_instance(with_instance=False) is None
        assert ssh.init_instance(with_instance=True) is None
        ssh.wait_until_initialization()
        ssh.spe_driver.terminate_instance()

    def test_manage_instance_gcp(self):
        ssh = self.get_testing_ssh('gcp')
        assert ssh.manage_instance() is None
        assert ssh.manage_instance() is None
        ssh.wait_until_initialization()
        ssh.spe_driver.terminate_instance()

    def test_attach_to_instance_gcp(self):
        self.fail()

    def test_finish_action_gcp(self):
        self.fail()

    def test_rsync_to_instance_gcp(self):
        self.fail()

    def test_rsync_back_to_local_gcp(self):
        self.fail()


