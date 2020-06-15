import logging
import os
from unittest import TestCase

import coloredlogs
from dotenv import dotenv_values, find_dotenv

from sshcrosscloud import utils
from sshcrosscloud.libcloud_extended import ProviderSpecific
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud


class TestSpecificAWS(TestCase):
    default_args = utils.default_args

    def get_testing_ssh_specific(self) -> ProviderSpecific:
        args = self.default_args
        logging.getLogger().setLevel(logging.INFO)
        coloredlogs.install(level='INFO')
        ssh_vars = utils.SSHVar(args)
        ssh_vars.provider = 'aws'
        ssh = SSHCrossCloud(ssh_vars, dotenv_values(find_dotenv()), os.environ)
        ssh.init_provider_specifics()
        ssh_spe = ssh.spe_driver
        return ssh_spe

    def test_create_instance(self):
        self.fail()

    def test__init_rsa_key_pair(self):
        self.fail()

    def test__init_size(self):
        self.fail()

    def test__init_image(self):
        self.fail()

    def test__init_security_group(self):
        self.fail()


class TestSpecificAzure(TestCase):
    default_args = utils.default_args

    def get_testing_ssh_specific(self) -> ProviderSpecific:
        args = self.default_args
        logging.getLogger().setLevel(logging.INFO)
        coloredlogs.install(level='INFO')
        ssh_vars = utils.SSHVar(args)
        ssh_vars.provider = 'azure'
        ssh = SSHCrossCloud(ssh_vars, dotenv_values(find_dotenv()), os.environ)
        ssh.init_provider_specifics()
        ssh_spe = ssh.spe_driver
        return ssh_spe

    def test_create_instance(self):
        self.fail()

    def test__init_rsa_key_pair(self):
        self.fail()

    def test__init_size(self):
        self.fail()

    def test__init_image(self):
        self.fail()

    def test__init_location(self):
        self.fail()

    def test__init_resource_group(self):
        self.fail()

    def test__init_auth(self):
        self.fail()

    def test__init_virtual_network(self):
        self.fail()

    def test__init_security_group(self):
        self.fail()

    def test__init_public_ip(self):
        self.fail()

    def test__init_network_interface(self):
        self.fail()


class TestSpecificGPC(TestCase):
    default_args = utils.default_args

    def get_testing_ssh_specific(self) -> ProviderSpecific:
        args = self.default_args
        logging.getLogger().setLevel(logging.INFO)
        coloredlogs.install(level='INFO')
        ssh_vars = utils.SSHVar(args)
        ssh_vars.provider = 'gcp'
        ssh = SSHCrossCloud(ssh_vars, dotenv_values(find_dotenv()), os.environ)
        ssh.init_provider_specifics()
        ssh_spe = ssh.spe_driver
        return ssh_spe

    def test_create_instance(self):
        self.fail()

    def test__init_rsa_key_pair(self):
        spe_driver = self.get_testing_ssh_specific()
        assert spe_driver._init_rsa_key_pair() is None

    def test__init_size(self):
        self.fail()

    def test__init_image(self):
        self.fail()

    def test__init_metadata(self):
        self.fail()
