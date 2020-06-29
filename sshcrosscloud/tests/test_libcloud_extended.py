import logging
import os
from unittest import TestCase

import coloredlogs
from dotenv import dotenv_values, find_dotenv
import unittest.mock

import sshcrosscloud
from sshcrosscloud import utils
from sshcrosscloud.libcloud_extended import ProviderSpecific, SpecificAWS, get_provider_specific_driver
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud
import libcloud.compute.drivers.ec2
import libcloud.compute.drivers.azure_arm
import libcloud.compute.base
import libcloud.compute.providers


def side_effect_create_local_rsa_key_pair_no_key(path):
    if path == "a":
        return False
    if path == "a.pub":
        return False


def side_effect_create_local_rsa_key_pair_private(path):
    if path == "a":
        return True
    if path == "a.pub":
        return False


class FakeProviderDriver:
    def __init__(self):
        self.node_id = None
        self.volume_name = None
        self.list_nodes_empty = False
        self.node_state = None
        self.terminate = True
        self.stop = True
        self.start = True
        self.list_nodes_called = False
        self.ex_stop_node_called = False
        self.ex_start_node_called = False
        self.destroy_node_called = False
        self.destroy_volume_called = False

    def list_nodes(self, arg=None):
        self.list_nodes_called = True
        if self.list_nodes_empty:
            return None
        else:
            return_value = [type('node', (), {})()]
            return_value[0].id = self.node_id
            return_value[0].state = self.node_state
            return return_value

    def list_volumes(self, ex_resource_group=None):
        return_value = [type('volume', (), {})()]
        return_value[0].name = self.volume_name
        return return_value

    def ex_stop_node(self, node):
        self.ex_stop_node_called = True
        return self.stop

    def ex_start_node(self, node):
        self.ex_start_node_called = True
        return self.start

    def destroy_node(self, node=None, ex_destroy_vhd=False, ex_destroy_nic=False):
        self.destroy_node_called = True
        return self.terminate

    def destroy_volume(self, arg=None):
        self.destroy_volume_called = True
        return


class TestProviderSpecific(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestProviderSpecific, self).__init__(*args, **kwargs)
        self.command_arg = utils.default_args

    @unittest.mock.patch('os.system')
    @unittest.mock.patch('os.chmod')
    @unittest.mock.patch('os.path.isfile', side_effect=side_effect_create_local_rsa_key_pair_no_key)
    def test_create_local_rsa_key_pair_no_key(self, is_path_file, os_chmod, os_system):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.rsa_private_key_file_path = "a"
        ssh.spe_driver.create_local_rsa_key_pair()
        os_system.assert_called_with("ssh-keygen -b 2048 -f a")
        os_chmod.assert_called()
        is_path_file.assert_called()

    @unittest.mock.patch('os.system')
    @unittest.mock.patch('os.chmod')
    @unittest.mock.patch('os.path.isfile', side_effect=side_effect_create_local_rsa_key_pair_private)
    def test_create_local_rsa_key_pair_private_key(self, isfile, chmod, os_system):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.rsa_private_key_file_path = "a"
        ssh.spe_driver.create_local_rsa_key_pair()
        os_system.assert_called_with("ssh-keygen -b 2048 -y -f a > a.pub")

    @unittest.mock.patch('os.path.isfile')
    def test_create_local_rsa_key_pair_private_key_and_public_key(self, isfile):
        ssh = SSHCrossCloud(**self.command_arg)
        isfile.return_value = True
        ssh.ssh_params.rsa_private_key_file_path = "a"
        assert ssh.spe_driver.create_local_rsa_key_pair() is None

    def test_stop_instance_no_arg(self):
        ssh = SSHCrossCloud(**self.command_arg)

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "terminated"
        ssh.spe_driver.driver.stop = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.stop_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.ex_stop_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "a"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.stop = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.stop_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.ex_stop_node_called is True

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.stop = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.stop_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.ex_stop_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "terminated"
        ssh.spe_driver.driver.stop = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.stop_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.ex_stop_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "a"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.stop = False
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        with self.assertRaises(Exception):
            ssh.spe_driver.stop_instance_no_arg()

    def test_start_instance_no_arg(self):
        ssh = SSHCrossCloud(**self.command_arg)

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "not_stopped"
        ssh.spe_driver.driver.start = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.start_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.ex_start_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "a"
        ssh.spe_driver.driver.node_state = "stopped"
        ssh.spe_driver.driver.start = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.start_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.ex_start_node_called is True

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "stopped"
        ssh.spe_driver.driver.start = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.start_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.ex_start_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "not_stopped"
        ssh.spe_driver.driver.start = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.start_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.ex_start_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "a"
        ssh.spe_driver.driver.node_state = "stopped"
        ssh.spe_driver.driver.start = False
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        with self.assertRaises(Exception):
            ssh.spe_driver.start_instance_no_arg()

    def test_terminate_instance_no_arg(self):
        ssh = SSHCrossCloud(**self.command_arg)

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "terminated"
        ssh.spe_driver.driver.terminate = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.terminate_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.destroy_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "a"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.terminate = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.terminate_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.destroy_node_called is True

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.terminate = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.terminate_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.destroy_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "terminated"
        ssh.spe_driver.driver.terminate = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        assert ssh.spe_driver.terminate_instance_no_arg() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.destroy_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "a"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.terminate = False
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        with self.assertRaises(Exception):
            ssh.spe_driver.terminate_instance_no_arg()

    def test_get_node_any_arg(self):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = 'foo'
        ssh.ssh_params.sshcrosscloud_instance_id = 'foo'
        assert ssh.spe_driver.get_node_any_arg().id == 'foo'

        ssh.spe_driver.driver.list_nodes_empty = True
        with self.assertRaises(Exception):
            ssh.spe_driver.get_node_any_arg()

        ssh.spe_driver.driver.node_id = 'foo'
        with self.assertRaises(Exception):
            ssh.spe_driver.get_node_any_arg()


class TestSpecificAWS(TestCase):
    command_arg = utils.default_args

    @unittest.mock.patch('libcloud.compute.drivers.ec2.EC2NodeDriver')
    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS, 'get_credentials')
    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS,
                                'get_region_from_config_file')
    def test_init_specific(self, get_region, get_credentials, ec2_node_driver):
        os.environ['IMAGE_NAME'] = 'Fedora'
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.aws.region = None
        get_credentials.return_value = "test1", "test2"
        ssh.spe_driver = get_provider_specific_driver(ssh.ssh_params)
        assert ssh.spe_driver.init_specific() is not None
        assert ssh.ssh_params.instance_user == "fedora"
        get_region.assert_called()
        get_credentials.assert_called()
        ec2_node_driver.assert_called()

    @unittest.mock.patch('os.path.isfile')
    @unittest.mock.patch('configparser.ConfigParser')
    def test_get_region(self, config_parser, is_file):
        is_file.return_value = True
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.spe_driver = get_provider_specific_driver(ssh.ssh_params)
        assert ssh.spe_driver.get_region_from_config_file() is not None
        config_parser.assert_called()

    @unittest.mock.patch('os.path.isfile')
    @unittest.mock.patch('configparser.ConfigParser')
    def test_get_credentials(self, config_parser, is_file):
        is_file.return_value = True
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.spe_driver = get_provider_specific_driver(ssh.ssh_params)
        assert len(ssh.spe_driver.get_credentials()) is 2
        config_parser.assert_called()


class TestSpecificAzure(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestSpecificAzure, self).__init__(*args, **kwargs)
        self.command_arg = utils.default_args
        self.command_arg['provider'] = 'azure'

    @unittest.mock.patch('os.path.isfile')
    @unittest.mock.patch('configparser.ConfigParser')
    def test_get_credentials(self, config_parser, is_file):
        is_file.return_value = True
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.spe_driver = get_provider_specific_driver(ssh.ssh_params)
        assert len(ssh.spe_driver.get_credentials()) is 4
        config_parser.assert_called()

    def test_terminate_instance(self):
        ssh = SSHCrossCloud(**self.command_arg)

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "terminated"
        ssh.spe_driver.driver.terminate = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        ssh.ssh_params.general_name = 'foo'
        ssh.spe_driver.driver.volume_name = 'foo'
        assert ssh.spe_driver.terminate_instance() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.destroy_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "a"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.terminate = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        ssh.ssh_params.general_name = 'foo'
        ssh.spe_driver.driver.volume_name = 'foo'
        assert ssh.spe_driver.terminate_instance() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.destroy_node_called is True

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.terminate = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        ssh.ssh_params.general_name = 'foo'
        ssh.spe_driver.driver.volume_name = 'foo'
        assert ssh.spe_driver.terminate_instance() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.destroy_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "b"
        ssh.spe_driver.driver.node_state = "terminated"
        ssh.spe_driver.driver.terminate = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        ssh.ssh_params.general_name = 'foo'
        ssh.spe_driver.driver.volume_name = 'foo'
        assert ssh.spe_driver.terminate_instance() is None
        assert ssh.spe_driver.driver.list_nodes_called is True
        assert ssh.spe_driver.driver.destroy_node_called is False

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "a"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.terminate = False
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        ssh.ssh_params.general_name = 'foo'
        ssh.spe_driver.driver.volume_name = 'foo'
        with self.assertRaises(Exception):
            ssh.spe_driver.terminate_instance()

        ssh.spe_driver.driver = FakeProviderDriver()
        ssh.spe_driver.driver.node_id = "a"
        ssh.spe_driver.driver.node_state = "not_terminated"
        ssh.spe_driver.driver.terminate = True
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        ssh.ssh_params.general_name = 'foo'
        ssh.spe_driver.driver.volume_name = 'foo'
        ssh.spe_driver.terminate_instance()
        assert ssh.spe_driver.driver.destroy_volume_called is True


class TestSpecificGPC(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestSpecificGPC, self).__init__(*args, **kwargs)
        self.command_arg = utils.default_args
        self.command_arg['provider'] = 'gcp'

    @unittest.mock.patch('os.path.isfile')
    @unittest.mock.patch('configparser.ConfigParser')
    def test_get_credentials(self, config_parser, is_file):
        is_file.return_value = True
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.spe_driver = get_provider_specific_driver(ssh.ssh_params)
        assert len(ssh.spe_driver.get_credentials()) is 4
        config_parser.assert_called()
