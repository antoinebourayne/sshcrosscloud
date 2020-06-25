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
    def test_create_local_rsa_key_pair_private_key(self, os_system):
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

    @unittest.mock.patch.object(libcloud.compute.drivers.ec2.BaseEC2NodeDriver, 'ex_stop_node')
    @unittest.mock.patch.object(libcloud.compute.drivers.ec2.BaseEC2NodeDriver, 'list_nodes')
    def test_stop_instance_no_arg(self, list_nodes, ex_stop_node):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.init_provider_specifics()
        list_nodes.return_value = [type('test', (), {})()]

        list_nodes.return_value[0].id = "b"
        list_nodes.return_value[0].state = "nothing"
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        ssh.spe_driver.stop_instance_no_arg()
        list_nodes.assert_called()
        assert not ex_stop_node.called

        list_nodes.return_value[0].id = "a"
        list_nodes.return_value[0].state = "terminated"
        ssh.spe_driver.stop_instance_no_arg()
        list_nodes.assert_called()
        assert not ex_stop_node.called

        list_nodes.return_value[0].id = "a"
        list_nodes.return_value[0].state = "nothing"
        ssh.spe_driver.stop_instance_no_arg()
        list_nodes.assert_called()
        ex_stop_node.assert_called()

    @unittest.mock.patch.object(libcloud.compute.drivers.ec2.BaseEC2NodeDriver, 'ex_start_node')
    @unittest.mock.patch.object(libcloud.compute.drivers.ec2.BaseEC2NodeDriver, 'list_nodes')
    def test_start_instance_no_arg(self, list_nodes, ex_start_node):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.init_provider_specifics()
        list_nodes.return_value = [type('test', (), {})()]

        list_nodes.return_value[0].id = "b"
        list_nodes.return_value[0].state = "nothing"
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        ssh.spe_driver.start_instance_no_arg()
        list_nodes.assert_called()
        assert not ex_start_node.called

        list_nodes.return_value[0].id = "a"
        list_nodes.return_value[0].state = "nothing"
        ssh.spe_driver.start_instance_no_arg()
        list_nodes.assert_called()
        assert not ex_start_node.called

        list_nodes.return_value[0].id = "a"
        list_nodes.return_value[0].state = "stopped"
        ssh.spe_driver.start_instance_no_arg()
        list_nodes.assert_called()
        ex_start_node.assert_called()

    @unittest.mock.patch.object(libcloud.compute.drivers.ec2.BaseEC2NodeDriver, 'destroy_node')
    @unittest.mock.patch.object(libcloud.compute.drivers.ec2.BaseEC2NodeDriver, 'list_nodes')
    def test_terminate_instance_no_arg(self, list_nodes, destroy_node):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.init_provider_specifics()
        list_nodes.return_value = [type('test', (), {})()]

        list_nodes.return_value[0].id = "b"
        list_nodes.return_value[0].state = "nothing"
        ssh.ssh_params.sshcrosscloud_instance_id = "a"
        ssh.spe_driver.terminate_instance_no_arg()
        list_nodes.assert_called()
        assert not destroy_node.called

        list_nodes.return_value[0].id = "a"
        list_nodes.return_value[0].state = "terminated"
        ssh.spe_driver.terminate_instance_no_arg()
        list_nodes.assert_called()
        assert not destroy_node.called

        list_nodes.return_value[0].id = "a"
        list_nodes.return_value[0].state = "nothing"
        ssh.spe_driver.terminate_instance_no_arg()
        list_nodes.assert_called()
        destroy_node.assert_called()


class TestSpecificAWS(TestCase):
    command_arg = utils.default_args

    @unittest.mock.patch('libcloud.compute.drivers.ec2.EC2NodeDriver')
    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS, 'get_credentials')
    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS, 'get_region_from_config_file')
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
        # TODO: bug list_nodes

    @unittest.mock.patch('libcloud.compute.drivers.ec2.BaseEC2NodeDriver')
    def test_get_node(self, ec2_driver):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.spe_driver = get_provider_specific_driver(ssh.ssh_params)
        ssh.spe_driver.driver = ec2_driver
        ssh.spe_driver.driver.list_nodes.return_value = [type('test', (), {})()]
        ssh.spe_driver.driver.list_nodes.return_value[0].id = 'test_instance_id'
        ssh.ssh_params.sshcrosscloud_instance_id = 'test_instance_id'
        assert ssh.spe_driver.get_node().id == 'test_instance_id'

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
        assert ssh.spe_driver.get_region_from_config_file() is not None
        config_parser.assert_called()


class TestSpecificAzure(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestSpecificAzure, self).__init__(*args, **kwargs)
        self.command_arg = utils.default_args
        self.command_arg['provider'] = 'azure'

    @unittest.mock.patch('libcloud.compute.drivers.azure_arm.AzureNodeDriver')
    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAzure, 'get_credentials')
    def test_init_specific(self, get_credentials, azure_node_driver):
        ssh = SSHCrossCloud(**self.command_arg)
        get_credentials.return_value = "test1", "test2", "test3", "test4"
        ssh.spe_driver = get_provider_specific_driver(ssh.ssh_params)
        assert ssh.spe_driver.init_specific() is not None
        get_credentials.assert_called()
        azure_node_driver.assert_called()
        # TODO: bug list_nodes

    def test_get_node(self):
        self.fail()

    def test_get_credentials(self):
        self.fail()

    def test_start_instance(self):
        self.fail()

    def test_stop_instance(self):
        self.fail()

    def test_terminate_instance(self):
        self.fail()


class TestSpecificGPC(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestSpecificGPC, self).__init__(*args, **kwargs)
        self.command_arg = utils.default_args
        self.command_arg['provider'] = 'gcp'

    def test_init_specific(self):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.init_provider_specifics()

    def test_get_node(self):
        self.fail()

    def test_get_credentials(self):
        self.fail()
