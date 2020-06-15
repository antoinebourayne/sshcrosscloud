import configparser
import logging
import os
import stat
import sys
from abc import ABC, abstractmethod
from pathlib import Path

import sshcrosscloud.utils as utils
from libcloud.compute.base import NodeAuthSSHKey
from sshcrosscloud.utils import get_public_key

"""
ProviderSpecific Class

This class is an upgrade of libcloud to simplify the use of SSH CROSS CLOUD
"""


class ProviderSpecific(ABC):
    ssh_vars = None
    driver = None

    @abstractmethod
    def create_instance(self):
        """

        :return:
        """
        pass

    @abstractmethod
    def get_node(self):
        """

        :return:
        """
        pass

    @abstractmethod
    def display_instances(self):
        """

        :return:
        """
        pass

    @abstractmethod
    def _init_rsa_key_pair(self):
        """

        :return:
        """
        pass

    @abstractmethod
    def spe_wait_until_running(self, nodes):
        """

        :return:
        """
        pass

    @abstractmethod
    def start_instance(self):
        """

        :return:
        """
        pass

    @abstractmethod
    def stop_instance(self):
        """

        :return:
        """
        pass

    @abstractmethod
    def terminate_instance(self):
        """

        :return:
        """
        pass

    @abstractmethod
    def get_credentials(self):
        """

        :return:
        """
        pass

    def write_credentials(self, credentials: dict):
        if not credentials:
            logging.info("Skip writting credentials")
        else:
            config = configparser.ConfigParser()
            config['default'] = credentials
            with open(self.ssh_vars.credentials_file_path, 'w') as cred_file:
                config.write(cred_file)
            logging.info("Credentials have been saved")

    def create_local_rsa_key_pair(self):
        genrate_key_pair = "ssh-keygen -f " + self.ssh_vars.rsa_key_file_path

        pub_from_priv = "ssh-keygen -y -f " + self.ssh_vars.rsa_key_file_path \
                        + " > " + self.ssh_vars.rsa_key_file_path + ".pub"

        if os.path.isfile(self.ssh_vars.rsa_key_file_path):
            if os.path.isfile(self.ssh_vars.rsa_key_file_path + ".pub"):
                logging.info("Using key pair : " + self.ssh_vars.rsa_key_file_path + ".pub")
            else:
                logging.info("Creating key pair from existing key in " + self.ssh_vars.rsa_key_file_path)
                return_code = os.system(pub_from_priv)
                if return_code == 0:
                    logging.info("Public Key created: " + self.ssh_vars.rsa_key_file_path + ".pub")
                else:
                    raise Exception("Error while creating public key from private key : " + str(return_code))

        else:
            return_code = os.system(genrate_key_pair)
            if return_code == 0:
                logging.info("Key pair created : " + self.ssh_vars.rsa_key_file_path)
                os.chmod(self.ssh_vars.rsa_key_file_path, stat.S_IRWXU)
                return
            else:
                raise Exception("Error while creating key pair : " + str(return_code))

    def display_instances_no_arg(self):
        nodes = self.driver.list_nodes()
        if not nodes:
            print("No instance running")
        print("------------------------------------------------------")
        for node in nodes:
            print(node)
        print("------------------------------------------------------")

    def stop_instance_no_arg(self) -> None:
        nodes = self.driver.list_nodes()
        if not nodes:
            logging.info("No instance running")

        for node in nodes:
            if node.id == self.ssh_vars.sshcrosscloud_instance_id and node.state != "terminated":
                terminate = self.driver.ex_stop_node(node)
                if terminate:
                    logging.warning("Stopped : " + node.id)
                    return
                else:
                    raise Exception("An error has occurred while stopping instance")
        return

    def start_instance_no_arg(self) -> None:
        """
        Starts a stopped instance
        :param ssh:
        :return:
        """
        nodes = self.driver.list_nodes()
        if not nodes:
            logging.info("No instance running")

        for node in nodes:
            if node.id == self.ssh_vars.sshcrosscloud_instance_id and node.state == "stopped":
                start = self.driver.ex_start_node(node)
                if start:
                    logging.info("Started : " + node.id)
                    return
                else:
                    raise Exception("An error has occurred while starting instance")
        return

    def terminate_instance_no_arg(self) -> None:
        """
        Terminates all owner's instances
        :param ssh:
        :return:
        """
        nodes = self.driver.list_nodes()
        for node in nodes:
            if node.id == self.ssh_vars.sshcrosscloud_instance_id and node.state != "terminated":
                if self.ssh_vars.provider == 'AZURE':
                    stop = self.driver.destroy_node(node=node, ex_destroy_vhd=True, ex_destroy_nic=False)
                    volumes = self.driver.list_volumes(ex_resource_group=self.ssh_vars.azure.resource_group)
                    volume = [v for v in volumes if "sshcrosscloud" in v.name][0]
                    self.driver.destroy_volume(volume)
                else:
                    stop = self.driver.destroy_node(node=node)
                if stop:
                    logging.warning("Terminated : " + node.id)
                    return
                else:
                    raise Exception("An error has occurred while terminating instance")
        return


class SpecificAWS(ProviderSpecific):
    def __init__(self, ssh_vars):
        self.ssh_vars = ssh_vars
        self.driver = None

    def create_instance(self):

        self._init_rsa_key_pair()
        self._init_size()
        self._init_image()
        self._init_security_group()

        logging.info("Instance parameters : " + self.ssh_vars.instance_name + " - " + self.ssh_vars.aws.image_id
                     + " - " + self.ssh_vars.aws.size)

        node = self.driver.create_node(name=self.ssh_vars.instance_name,
                                       image=self.image,  # Need to use Libcloud object, can't use string
                                       size=self.size,
                                       ex_userdata=self.ssh_vars.user_data,
                                       ex_keyname=self.ssh_vars.username,
                                       ex_securitygroup=[self.security_group.name])

        return node

    def get_node(self):
        nodes = self.driver.list_nodes()
        if not nodes:
            raise Exception("No instance found")
        if self.ssh_vars.sshcrosscloud_instance_id:
            for node in nodes:
                if node.id == self.ssh_vars.sshcrosscloud_instance_id:
                    return node
            raise Exception("No instance found")
        else:
            raise Exception("No instance ID registered")

    def get_region(self):
        if os.path.isfile(self.ssh_vars.aws.config_path):

            config = configparser.ConfigParser()
            config.read(self.ssh_vars.aws.config_path)
            aws_region = config['default']['region']

            return aws_region
        else:
            raise Exception("No region found in " + self.ssh_vars.aws.config_path
                            + ", run sshcrosscloud --config -- provider aws")

    def start_instance(self):
        self.start_instance_no_arg()

    def stop_instance(self):
        self.stop_instance_no_arg()

    def terminate_instance(self):
        self.terminate_instance_no_arg()

    def display_instances(self):
        self.display_instances_no_arg()

    def spe_wait_until_running(self, nodes):
        return self.driver.wait_until_running(nodes=nodes)[0]

    def get_credentials(self):
        if os.path.isfile(self.ssh_vars.credentials_file_path):

            config = configparser.ConfigParser()
            config.read(self.ssh_vars.credentials_file_path)
            aws_access_key_id = config['default']['aws_access_key_id']
            aws_secret_access_key = config['default']['aws_secret_access_key']

            return aws_access_key_id, aws_secret_access_key
        else:
            raise Exception("No credentials found in " + self.ssh_vars.credentials_file_path +
                            ", run sshcrosscloud --config -- provider aws")

    def _init_rsa_key_pair(self):
        logging.info("Creating key pair")

        if os.path.isfile(self.ssh_vars.rsa_key_file_path):
            for key in self.driver.ex_list_keypairs():
                if self.ssh_vars.rsa_key_name == key['keyName']:
                    logging.info("Key pair already stored")
                    return

            logging.info("Creating key pair from existing key in " + self.ssh_vars.rsa_key_file_path)
            self.driver.import_key_pair_from_file(name=self.ssh_vars.rsa_key_name,
                                                  key_file_path=self.ssh_vars.rsa_key_file_path)
            return
        else:
            keypair = self.driver.create_key_pair(name=self.ssh_vars.rsa_key_name)  # TODO: ask password to user ?
            rsa_key = keypair.private_key

            with open(self.ssh_vars.rsa_key_file_path, 'w') as file:
                file.write(rsa_key)
            os.chmod(self.ssh_vars.rsa_key_file_path, stat.S_IRWXU)

            logging.info("Key pair created : " + self.ssh_vars.rsa_key_file_path)

    def _init_size(self):
        sizes = self.driver.list_sizes()
        selected_sizes = [s for s in sizes if s.id == self.ssh_vars.aws.size]
        if not selected_sizes:
            raise Exception(self.ssh_vars.aws.size + " is not available in AWS")
        else:
            self.size = selected_sizes[0]

    def _init_image(self):
        images = self.driver.list_images()
        selected_images = [i for i in images if i.id == self.ssh_vars.aws.image_id]
        if not selected_images:
            raise Exception(self.ssh_vars.aws.image_id + " is not available in AWS")
        else:
            self.image = selected_images[0]

    def _init_security_group(self):
        group_names = [self.ssh_vars.aws.security_group]
        security_groups = self.driver.ex_get_security_groups(group_names=group_names)
        if not security_groups:
            answer = utils.get_ui_confirmation("No security group found, would you like to create one?")
            if answer:
                security_group_lst = self.driver.ex_create_security_group(
                    self.ssh_vars.aws.security_group,
                    self.ssh_vars.aws.security_group + " security group")
                if not security_group_lst.get('group_id'):
                    raise Exception("Could not create security group")
                else:
                    security_groups = self.driver.ex_get_security_groups(
                        group_ids=security_group_lst.get('group_id'))
            else:
                logging.info("No security group created")

        self.security_group = security_groups[0]


class SpecificAzure(ProviderSpecific):
    def __init__(self, ssh_vars):
        self.ssh_vars = ssh_vars
        self.driver = None

    def create_instance(self):
        self._init_rsa_key_pair()
        self._init_location()
        self._init_size()
        self._init_image()
        self._init_auth()
        self._init_resource_group()
        self._init_virtual_network()
        self._init_security_group()
        self._init_public_ip()
        self._init_network_interface()

        # Node Creation
        logging.info("Instance parameters : " + self.ssh_vars.instance_name + " - "
                     + self.image.name + " - " + self.size.name)

        node = self.driver.create_node(name=self.ssh_vars.instance_name,
                                       image=self.image,
                                       size=self.size,
                                       ex_user_name=self.ssh_vars.instance_user,
                                       auth=self.auth,
                                       ex_resource_group=self.resource_group.name,
                                       ex_network=self.virtual_network.name,
                                       ex_use_managed_disks=True,
                                       ex_nic=self.network_interface,
                                       location=self.location,
                                       # this argument is useless, but libcloud requires it
                                       ex_storage_account="useless")

        return node

    def get_node(self):
        nodes = self.driver.list_nodes(self.ssh_vars.azure.resource_group)
        if not nodes:
            raise Exception("No instance found")
        if self.ssh_vars.sshcrosscloud_instance_id:
            for node in nodes:
                if node.id == self.ssh_vars.sshcrosscloud_instance_id:
                    return node
            raise Exception("No instance found")
        else:
            raise Exception("No instance ID registered")

    def get_credentials(self):
        if os.path.isfile(self.ssh_vars.credentials_file_path):

            config = configparser.ConfigParser()
            config.read(self.ssh_vars.credentials_file_path)
            tenant_id = config['default']['tenant']
            subscription_id = config['default']['subscription_id']
            client_id = config['default']['client_id']
            secret = config['default']['secret']

            return tenant_id, subscription_id, client_id, secret
        else:
            raise Exception(
                "No credentials found in " + self.ssh_vars.credentials_file_path + ", run sshcrosscloud --config -- provider azure")

    def start_instance(self) -> None:
        nodes = self.driver.list_nodes(self.ssh_vars.azure.resource_group)
        if not nodes:
            logging.info("No instance running")
        for node in nodes:
            if node.id == self.ssh_vars.sshcrosscloud_instance_id and node.state == "stopped":
                start = self.driver.ex_start_node(node)
                if start:
                    logging.info("Started : " + node.id)
                    return
                else:
                    raise Exception("An error has occurred while starting instance")
        return

    def stop_instance(self) -> None:
        nodes = self.driver.list_nodes(self.ssh_vars.azure.resource_group)
        if not nodes:
            logging.info("No instance running")
        for node in nodes:
            if node.id == self.ssh_vars.sshcrosscloud_instance_id and node.state != "terminated":
                terminate = self.driver.ex_stop_node(node)
                if terminate:
                    logging.warning("Stopped : " + node.id)
                    return
                else:
                    raise Exception("An error has occurred while stopping instance")
        return

    def terminate_instance(self) -> None:
        nodes = self.driver.list_nodes(self.ssh_vars.azure.resource_group)
        for node in nodes:
            if node.id == self.ssh_vars.sshcrosscloud_instance_id and node.state != "terminated":
                if self.ssh_vars.provider == 'azure':
                    stop = self.driver.destroy_node(node=node, ex_destroy_vhd=True, ex_destroy_nic=False)
                    volumes = self.driver.list_volumes(ex_resource_group=self.ssh_vars.azure.resource_group)
                    volume = [v for v in volumes if "sshcrosscloud" in v.name][0]
                    self.driver.destroy_volume(volume)
                else:
                    stop = self.driver.destroy_node(node=node)
                if stop:
                    logging.warning("Terminated : " + node.id)
                    return
                else:
                    raise Exception("An error has occurred while terminating instance")
        return

    def display_instances(self):
        nodes = self.driver.list_nodes(self.ssh_vars.azure.resource_group)
        if not nodes:
            print("No instance running")
        print("------------------------------------------------------")
        for node in nodes:
            print(node)
        print("------------------------------------------------------")

    def spe_wait_until_running(self, nodes):
        list_node_args = {'ex_resource_group': 'NetworkWatcherRG'}
        return self.driver.wait_until_running(nodes=nodes, ex_list_nodes_kwargs=list_node_args)[0]

    def _init_rsa_key_pair(self):
        self.create_local_rsa_key_pair()

    def _init_size(self):
        sizes = self.driver.list_sizes(self.location)
        selected_sizes = [s for s in sizes if s.id == self.ssh_vars.azure.size]
        if not selected_sizes:
            raise Exception(self.ssh_vars.azure.size + " is not available in Azure")
        else:
            self.size = selected_sizes[0]

    def _init_image(self):
        images = self.driver.list_images(location=self.location, ex_publisher=self.ssh_vars.azure.publisher)
        selected_images = [i for i in images if self.ssh_vars.azure.image_id in i.id]
        if not selected_images:
            raise Exception(self.ssh_vars.azure.image_id + " is not available in AWS")
        else:
            self.image = selected_images[0]

    def _init_location(self):
        locations = self.driver.list_locations()
        selected_locations = [loc for loc in locations if loc.id == self.ssh_vars.azure.region]
        if not selected_locations:
            raise Exception(self.ssh_vars.azure.region + " is not available in AWS")
        else:
            self.location = selected_locations[0]

    def _init_resource_group(self):
        rgs = self.driver.ex_list_resource_groups()
        selected_rg = [rg for rg in rgs if rg.name == self.ssh_vars.azure.resource_group]
        if not selected_rg:
            raise Exception(self.ssh_vars.azure.resource_group + " does not exist")
        else:
            self.resource_group = selected_rg[0]

    def _init_auth(self):
        # Libcloud does not allow key vault for Azure, therefore need to store public key locally
        self.auth = NodeAuthSSHKey(get_public_key(self.ssh_vars.rsa_key_file_path))

    def _init_virtual_network(self):
        if not self.driver.ex_list_networks():
            raise Exception("You must create a Virtual Network in Resource Group : " + self.resource_group.name)
        else:
            self.virtual_network = self.driver.ex_list_networks()[0]

    def _init_security_group(self):
        if not self.driver.ex_list_network_security_groups(resource_group=self.resource_group.name):
            logging.warning("No Security Group found, it is advised to create one for increased security.")
        else:
            self.security_group = \
                self.driver.ex_list_network_security_groups(resource_group=self.resource_group.name)[0]

    def _init_public_ip(self):
        pips = self.driver.ex_list_public_ips(resource_group=self.resource_group.name)
        selected_pips = [ip for ip in pips if ip.name == self.ssh_vars.azure.public_ip_name]
        if not selected_pips:
            answer = utils.get_ui_confirmation(self.ssh_vars.azure.public_ip_name + " ip does not exist, create one ?")
            if answer:
                public_ip = self.driver.ex_create_public_ip(self.ssh_vars.azure.public_ip_name,
                                                            resource_group=self.resource_group.name,
                                                            location=self.location,
                                                            public_ip_allocation_method="Dynamic")
                if not public_ip:
                    raise Exception("Error while creating ip")
            else:
                raise Exception("You need to create an IP")
        else:
            self.public_ip = selected_pips[0]

    def _init_network_interface(self):
        nics = self.network_interface = self.driver.ex_list_nics(resource_group=self.resource_group.name)
        selected_nics = [ni for ni in nics if ni.name == self.ssh_vars.azure.public_ip_name]
        if not selected_nics:
            sns = self.driver.ex_list_subnets(self.virtual_network)
            selected_nics = [sn for sn in sns if sn.name == self.ssh_vars.azure.subnet]
            if not selected_nics:
                raise Exception("You must create a Subnet '" + self.ssh_vars.azure.subnet + "' in Virtual Network : "
                                + self.virtual_network.name)
            else:
                sn = selected_nics[0]
                self.network_interface = self.driver.ex_create_network_interface(
                    name=self.ssh_vars.azure.network_interface,
                    resource_group=self.resource_group.name,
                    location=self.location,
                    public_ip=self.public_ip,
                    subnet=sn)
        else:
            self.network_interface = selected_nics[0]


class SpecificGPC(ProviderSpecific):
    def __init__(self, ssh_vars):
        self.ssh_vars = ssh_vars
        self.driver = None

    def create_instance(self):
        self._init_rsa_key_pair()
        self._init_image()
        self._init_size()
        self._init_metadata()

        logging.info("Instance parameters : " + self.ssh_vars.instance_name + " - " + self.image.name
                     + " - " + self.size.name)

        node = self.driver.create_node(name=self.ssh_vars.instance_name,
                                       image=self.image,
                                       size=self.size,
                                       ex_metadata=self.metadata)

        return node

    def get_node(self):
        nodes = self.driver.list_nodes()
        if not nodes:
            raise Exception("No instance found")
        if self.ssh_vars.sshcrosscloud_instance_id:
            for node in nodes:
                if node.id == self.ssh_vars.sshcrosscloud_instance_id:
                    return node
            raise Exception("No instance found")
        else:
            raise Exception("No instance ID registered")

    def get_credentials(self):
        if os.path.isfile(self.ssh_vars.credentials_file_path):
            config = configparser.ConfigParser()
            config.read(self.ssh_vars.credentials_file_path)
            user_id = config['default']['user_id']
            key = config['default']['key']
            project = config['default']['project']
            datacenter = config['default']['datacenter']

            return user_id, key, project, datacenter
        else:
            raise Exception(
                "No credentials found in " + self.ssh_vars.credentials_file_path
                + ", run sshcrosscloud --config -- provider gcp")

    def start_instance(self):
        self.start_instance_no_arg()

    def stop_instance(self):
        self.stop_instance_no_arg()

    def terminate_instance(self):
        self.terminate_instance_no_arg()

    def display_instances(self):
        self.display_instances_no_arg()

    def _init_rsa_key_pair(self):
        self.create_local_rsa_key_pair()

    def spe_wait_until_running(self, nodes):
        return self.driver.wait_until_running(nodes=nodes)[0]

    def _init_size(self):
        sizes = self.driver.list_sizes()
        selected_sizes = [s for s in sizes if self.ssh_vars.gcp.size in s.name]
        if not selected_sizes:
            raise Exception(self.ssh_vars.gcp.size + " is not available in GCP")
        else:
            self.size = selected_sizes[0]

    def _init_image(self):
        images = self.driver.list_images()
        selected_images = [i for i in images if self.ssh_vars.gcp.image_name in i.name]
        if not selected_images:
            raise Exception(self.ssh_vars.gcp.image_name + " is not available in GCP")
        else:
            self.image = selected_images[0]

    def _init_metadata(self):
        # Libcloud does not allow key vault for Azure, therefore need to store public key locally
        self.metadata = {
            "items": [
                {
                    "key": "ssh-keys",
                    "value": "antoinebourayne:" + get_public_key(self.ssh_vars.rsa_key_file_path)
                }
            ]
        }


def get_provider_specific_driver(ssh_vars: utils.SSHVar):
    if ssh_vars.provider == 'aws':
        return SpecificAWS(ssh_vars)

    if ssh_vars.provider == 'azure':
        return SpecificAzure(ssh_vars)

    if ssh_vars.provider == 'gcp':
        return SpecificGPC(ssh_vars)
