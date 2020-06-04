import logging
import os
import sys
import stat
from abc import ABC, abstractmethod
from pathlib import Path
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud
from libcloud.compute.base import NodeAuthSSHKey
from sshcrosscloud.utils import get_public_key

"""
ProviderSpecific Class

This class is an upgrade of libcloud to simplify the use of SSH CROSS CLOUD
"""


class ProviderSpecific(ABC):

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
    def _init_rsa_key_pair(self):
        """

        :return:
        """
        pass

    # TODO: to be integrated
    def create_local_rsa_key_pair(self):
        logging.info("Creating key pair")

        genrate_key_pair = "ssh-keygen -f " + str(Path.home()) + "/.ssh/" + self.ssh.env["USERNAME"]

        pub_from_priv = "ssh-keygen -y -f " + str(Path.home()) + "/.ssh/" \
                        + self.ssh.env["USERNAME"] + " > " + str(Path.home()) \
                        + "/.ssh/" + self.ssh.env["USERNAME"] + ".pub"

        if os.path.isfile(str(Path.home()) + "/.ssh" + self.ssh.env["USERNAME"]):
            if os.path.isfile(str(Path.home()) + "/.ssh" + self.ssh.env["USERNAME"] + ".pub"):
                logging.info("Key pair already stored")
            else:
                logging.info("Creating key pair from existing key in " + str(Path.home()) + "/.ssh" + self.ssh.env["USERNAME"])
                os.system(pub_from_priv)
        else:
            os.system(genrate_key_pair)
            os.chmod(str(Path.home()) + "/.ssh/" + self.ssh.env["USERNAME"], stat.S_IRWXU)

        if os.path.isfile(str(Path.home()) + "/.ssh/" + self.ssh.env["USERNAME"] + ".pub"):
            logging.info("Key pair created")
            return 0


class SpecificAWS(ProviderSpecific):
    def __init__(self, ssh):
        self.ssh = ssh
        self._init_size()
        self._init_image()
        self._init_security_group()

    def create_instance(self):
        logging.info("Instance parameters : " + self.ssh.env['INSTANCE_NAME'] + self.image + self.size)
        node = self.ssh.driver.create_node(name=self.ssh.env['INSTANCE_NAME'],
                                           image=self.image,  # Need to use Libcloud object, can't use string
                                           size=self.size,
                                           ex_userdata=self.ssh.env['USER_DATA'],
                                           ex_keyname=self.ssh.env["USERNAME"],
                                           ex_securitygroup=self.security_group)

        return node

    def get_node(self):
        nodes = self.ssh.driver.list_nodes()
        if not nodes:
            raise Exception("No instance found")
        if self.ssh.env.get('INSTANCE_ID'):
            for node in nodes:
                if node.id == self.ssh.env['INSTANCE_ID']:
                    return node
            raise Exception("No instance found")
        else:
            raise Exception("No instance ID registered")

    def _init_rsa_key_pair(self):
        logging.info("Creating key pair")

        if os.path.isfile(str(Path.home()) + "/.ssh" + self.ssh.env['USERNAME']):
            if self.ssh.env['USERNAME'] in self.ssh.driver.ex_list_keypairs():
                logging.info("Key pair already stored, ignoring step")
            else:
                logging.info(
                    "Creating key pair from existing key in " + str(Path.home()) + "/.ssh" + self.ssh.env['USERNAME'])
                self.ssh.driver.import_key_pair_from_file(name=self.ssh.env['USERNAME'],
                                                          key_file_path=str(Path.home())
                                                                        + "/.ssh" + self.ssh.env['USERNAME'])
        else:
            keypair = self.ssh.driver.create_key_pair(name=self.ssh.env['USERNAME'])
            rsa_key = keypair.get('KeyMaterial')

            with open(str(Path.home()) + "/.ssh/" + self.ssh.env['USERNAME'], 'w') as file:
                file.write(rsa_key)
            os.chmod(str(Path.home()) + "/.ssh/" + self.ssh.env['USERNAME'], stat.S_IRWXU)

            logging.info("Key pair created")

    def _init_size(self):
        sizes = self.ssh.driver.list_sizes()
        selected_sizes = [s for s in sizes if s.id == self.ssh.env['INSTANCE_TYPE']]
        if not selected_sizes:
            raise Exception(self.ssh.env['INSTANCE_TYPE'] + " is not available in AWS")
        else:
            self.size = selected_sizes[0]

    def _init_image(self):
        images = self.ssh.driver.list_images()
        selected_images = [i for i in images if i.id == self.ssh.env['IMAGE_ID']]
        if not selected_images:
            raise Exception(self.ssh.env['IMAGE_ID'] + " is not available in AWS")
        else:
            self.image = selected_images[0]

    def _init_security_group(self):
        group_names = [self.ssh.env.get('SECURITY_GROUP')]
        security_groups = self.ssh.driver.ex_get_security_groups(group_names=group_names)
        if not security_groups:
            logging.info("No security group found, would you like to create one? y/n")
            answer = input()
            if answer == 'y':
                security_group_lst = self.ssh.driver.ex_create_security_group(
                    self.ssh.env['SECURITY_GROUP'],
                    self.ssh.env['SECURITY_GROUP'] + " security group")
                if not security_group_lst.get('group_id'):
                    raise Exception("Could not create security group")
                else:
                    security_groups = self.ssh.driver.ex_get_security_groups(
                        group_ids=security_group_lst.get('group_id'))
            else:
                logging.info("No security group created")

        self.security_group = security_groups[0]


class SpecificAzure(ProviderSpecific):
    def __init__(self, ssh):
        self.ssh = ssh
        self._init_location()
        self._init_size()
        self._init_image()
        self._init_auth()
        self._init_resource_group()
        self._init_virtual_network()
        self._init_security_group()
        self._init_public_ip()
        self._init_network_interface()

    def create_instance(self):
        # Node Creation
        logging.info("Instance parameters : " + self.ssh.env['INSTANCE_NAME'] + self.image + self.size)
        node = self.ssh.driver.create_node(name=self.ssh.env['INSTANCE_NAME'],
                                           image=self.image,
                                           size=self.size,
                                           ex_user_name=self.ssh.env['INSTANCE_USER'],
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
        nodes = self.ssh.driver.list_nodes(self.ssh.env['AZ_RESOURCE_GROUP'])
        if not nodes:
            raise Exception("No instance found")
        if self.ssh.env.get('INSTANCE_ID'):
            for node in nodes:
                if node.id == self.ssh.env['INSTANCE_ID']:
                    return node
            raise Exception("No instance found")
        else:
            raise Exception("No instance ID registered")

    def _init_rsa_key_pair(self):
        self.create_local_rsa_key_pair()

    def _init_size(self):
        sizes = self.ssh.driver.list_sizes(self.location)
        selected_sizes = [s for s in sizes if s.id == self.ssh.env['INSTANCE_TYPE']]
        if not selected_sizes:
            raise Exception(self.ssh.env['INSTANCE_TYPE'] + " is not available in AWS")
        else:
            self.size = selected_sizes[0]

    def _init_image(self):
        images = self.ssh.driver.list_images(location=self.location, ex_publisher=self.ssh.env['AZ_PUBLISHER'])
        selected_images = [i for i in images if self.ssh.env['IMAGE_ID'] in i.id]
        if not selected_images:
            raise Exception(self.ssh.env['IMAGE_ID'] + " is not available in AWS")
        else:
            self.image = selected_images[0]

    def _init_location(self):
        locations = self.ssh.driver.list_locations()
        selected_locations = [l for l in locations if l.id == self.ssh.env['REGION']]
        if not selected_locations:
            raise Exception(self.ssh.env['REGION'] + " is not available in AWS")
        else:
            self.location = selected_locations[0]

    def _init_resource_group(self):
        rgs = self.ssh.driver.ex_list_resource_groups()
        selected_rg = [rg for rg in rgs if rg.name == self.ssh.env['AZ_RESOURCE_GROUP']]
        if not selected_rg:
            raise Exception(self.ssh.env['AZ_RESOURCE_GROUP'] + " does not exist")
        else:
            self.resource_group = selected_rg[0]

    def _init_auth(self):
        # Libcloud does not allow key vault for Azure, therefore need to store public key locally
        self.auth = NodeAuthSSHKey(get_public_key(self.ssh.env['USERNAME']))

    def _init_virtual_network(self):
        if not self.ssh.driver.ex_list_networks():
            raise Exception("You must create a Virtual Network in Resource Group : " + self.resource_group.name)
        else:
            self.virtual_network = self.ssh.driver.ex_list_networks()[0]

    def _init_security_group(self):
        if not self.ssh.driver.ex_list_network_security_groups(resource_group=self.resource_group.name):
            logging.warning("No Security Group found, it is advised to create one for increased security.")
        else:
            self.security_group = \
                self.ssh.driver.ex_list_network_security_groups(resource_group=self.resource_group.name)[0]

    def _init_public_ip(self):
        pips = self.ssh.driver.ex_list_public_ips(resource_group=self.resource_group.name)
        selected_pips = [ip for ip in pips if ip.name == self.ssh.env['AZ_PUBLIC_IP_NAME']]
        if not selected_pips:
            logging.warning(self.ssh.env['AZ_PUBLIC_IP_NAME'] + " ip does not exist, create one ? y/n")
            answer = input()
            if answer == 'y':
                public_ip = self.ssh.driver.ex_create_public_ip(self.ssh.env['AZ_PUBLIC_IP_NAME'],
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
        nics = self.network_interface = self.ssh.driver.ex_list_nics(resource_group=self.resource_group.name)
        selected_nics = [ni for ni in nics if ni.name == self.ssh.env['AZ_PUBLIC_IP_NAME']]
        if not selected_nics:
            sns = self.ssh.driver.ex_list_subnets(self.virtual_network)
            selected_nics = [sn for sn in sns if sn.name == self.ssh.env['AZ_SUBNET']]
            if not selected_nics:
                raise Exception("You must create a Subnet '" + self.ssh.env['AZ_SUBNET'] + "' in Virtual Network : "
                                + self.virtual_network.name)
            else:
                sn = selected_nics[0]
                self.network_interface = self.ssh.driver.ex_create_network_interface(name="sshcrosscloud-ni",
                                                                                     resource_group=self.resource_group.name,
                                                                                     location=self.location,
                                                                                     public_ip=self.public_ip,
                                                                                     subnet=sn)
        else:
            self.network_interface = selected_nics[0]


class SpecificGPC(ProviderSpecific):
    def __init__(self, ssh):
        self.ssh = ssh
        self._init_image()
        self._init_size()
        self._init_metadata()

    def create_instance(self):
        logging.info("Instance parameters : " + self.ssh.env['INSTANCE_NAME'] + self.image + self.size)
        node = self.ssh.driver.create_node(name=self.ssh.env['INSTANCE_NAME'],
                                           image=self.image,
                                           size=self.size,
                                           ex_metadata=self.metadata)

        return node

    def get_node(self):
        nodes = self.ssh.driver.list_nodes()
        if not nodes:
            raise Exception("No instance found")
        if self.ssh.env.get('INSTANCE_ID'):
            for node in nodes:
                if node.id == self.ssh.env['INSTANCE_ID']:
                    return node
            raise Exception("No instance found")
        else:
            raise Exception("No instance ID registered")

    def _init_rsa_key_pair(self):
        self.create_local_rsa_key_pair()

    def _init_size(self):
        sizes = self.ssh.driver.list_sizes()
        selected_sizes = [s for s in sizes if self.ssh.env["INSTANCE_TYPE"] in s.name]
        if not selected_sizes:
            raise Exception(self.ssh.env['INSTANCE_TYPE'] + " is not available in AWS")
        else:
            self.size = selected_sizes[0]

    def _init_image(self):
        images = self.ssh.driver.list_images()
        selected_images = [i for i in images if self.ssh.env['IMAGE_NAME'] in i.name]
        if not selected_images:
            raise Exception(self.ssh.env['IMAGE_ID'] + " is not available in AWS")
        else:
            self.image = selected_images[0]

    def _init_metadata(self):
        # Libcloud does not allow key vault for Azure, therefore need to store public key locally
        self.metadata = {
            "items": [
                {
                    "key": "ssh-keys",
                    "value": "antoinebourayne:" + get_public_key(self.ssh.env['USERNAME'])
                }
            ]
        }


def get_provider_specific_driver(ssh: SSHCrossCloud):
    if ssh.env['PROVIDER'] == 'AWS':
        return SpecificAWS(ssh)

    if ssh.env['PROVIDER'] == 'AZURE':
        return SpecificAzure(ssh)

    if ssh.env['PROVIDER'] == 'GCP':
        return SpecificGPC(ssh)
