import os
from unittest import TestCase

from dotenv import dotenv_values, find_dotenv

from sshcrosscloud import utils
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud


class TestSSHCrossCloud(TestCase):
    def test__init_env(self):
        pre_env = os.environ
        arg_dict = {'provider': 'aws'}
        ssh = SSHCrossCloud(pre_env, arg_dict)
        assert utils.aws_default_dict.items() <= ssh.env.items()
        assert dotenv_values(find_dotenv()).items() <= ssh.env.items()
        assert pre_env.items() <= ssh.env.items()

    def test__init_variables(self):
        self.fail()

    def test__init_provider_specifics(self):
        self.fail()

    def test__check_parameters(self):
        self.fail()

    def test__init_instance_attributes_from_name(self):
        self.fail()

    def test__init_driver(self):
        self.fail()

    def test__init_credentials_path(self):
        self.fail()

    def test_write_credentials(self):
        self.fail()

