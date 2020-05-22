import logging
from abc import ABC, abstractmethod
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud
from libcloud.compute.base import NodeAuthSSHKey

from sshcrosscloud.utils import get_public_key


class ProviderSpecific(ABC):

    def create_instance(self):
        pass

class SpecificAWS(ProviderSpecific):
    def __init__(self, ssh):
        self.ssh = ssh

    def create_instance(self):
        # Size
        sizes = self.ssh.driver.list_sizes()  # PPR: dans tous les cas, tu payes le cout de la requete.
        size = [s for s in sizes if s.id == self.ssh.env['INSTANCE_TYPE']][
            0]  # PPR: Si INSTANCE_TYPE, bug. Il faut un test pour cela
        # PPR: si la question est "est-ce que INSTANCE_TYPE est bon ? il faut ecrire le code uniquement pour cela !
        # Après le test, ssh.env['INSTANCE_TYPE'] peut être utilisé directement.

        # Image
        images = self.ssh.driver.list_images()
        image = [i for i in images if self.ssh.env['IMAGE_ID'] == i.id][0]  # IDEM

        # Security Group
        # PPR: la question est, si le SECURITY_GROUP n'existe pas, je fais quoi ? Erreur ou création sous ce nom ?
        security_groups = self.ssh.driver.ex_list_security_groups()  # PPR: cela coute. Est-ce indispensable ?
        if self.ssh.env.get('SECURITY_GROUP'):  # PPR: SECURITY_GROUP ou AWS_SECURITY_GROUP ?
            if self.ssh.env['SECURITY_GROUP'] in security_groups:
                security_group = self.ssh.env['SECURITY_GROUP']
            elif self.ssh.env['USERNAME'] in security_groups:  # PPR: Non c'est une faille de sécu.
                security_group = self.ssh.env['USERNAME']
            else:
                security_group = self.set_security_group() # changer en méthode
        else:
            self.ssh.env['SECURITY_GROUP'] = self.ssh.env['USERNAME']
            security_group = self.set_security_group() # changer en méthode

        # Node Creation
        node = self.ssh.driver.create_node(name=self.ssh.env['INSTANCE_NAME'],
                                      image=image,
                                      size=size,  # PPR: utiliser ssh.env['INSTANCE_TYPE']
                                      ex_userdata=self.ssh.env['USER_DATA'],
                                      ex_keyname=self.ssh.env["USERNAME"],
                                      ex_securitygroup=security_group)

        return node

    def set_security_group(self):  # PPR: c'est un set et il y a un return ?
        self.ssh.driver.ex_create_security_group(self.ssh.env['SECURITY_GROUP'], self.ssh.env[
            'SECURITY_GROUP'] + " security group")  # PPR: TU (test unitaire) en cas de difficulté de créer le SG. Déja existant, mauvais nom, nom vide, etc.
        security_groups = self.ssh.driver.ex_list_security_groups()  # PPR: Pas de double check, utiliser le code retour de  ex_create_security_group
        security_group = [sg for sg in security_groups if self.ssh.env['SECURITY_GROUP'] == sg][
            0]  # PPR: NON ssh.env['SECURITY_GROUP'].in security_groups !
        return security_group


class SpecificAzure(ProviderSpecific):
    def __init__(self, ssh):
        self.ssh = ssh

    def create_instance(self):
        # Location
        locations = self.ssh.driver.list_locations()
        location = [i for i in locations if i.id == self.ssh.env['REGION']][0]

        # Size
        sizes = self.ssh.driver.list_sizes(location)
        size = [s for s in sizes if self.ssh.env['INSTANCE_TYPE'] in s.id][0]

        # Image
        images = self.ssh.driver.list_images(location=location, ex_publisher="Canonical")
        image = [i for i in images if self.ssh.env['IMAGE_ID'] in i.id][0]

        # Auth
        auth = NodeAuthSSHKey(get_public_key(self.ssh.env['USERNAME']))

        # Resource Group
        if not self.ssh.driver.ex_list_resource_groups():
            logging.warning("You must create a Resource Group")
            return 1
        else:
            rg = self.ssh.driver.ex_list_resource_groups()[0]

        # Virtual Network
        if not self.ssh.driver.ex_list_networks():
            logging.warning("You must create a Virtual Network in Resource Group : " + rg.name)
            return 1
        else:
            vn = self.ssh.driver.ex_list_networks()[0]

        # Security Group
        if not self.ssh.driver.ex_list_network_security_groups(resource_group=rg.name):
            logging.warning("No Security Group found, it is advised to create one for increased security.")
        else:
            sg = self.ssh.driver.ex_list_network_security_groups(resource_group=rg.name)[0]

        # Public IP
        # PPR: pourquoi ne pas créer une IP spécifique à l'instance. On ne peut pas la partager avec une autre instance !!!
        if not self.ssh.driver.ex_list_public_ips(resource_group=rg.name):
            public_ip = self.ssh.driver.ex_create_public_ip("sshcrosscloud-ip", resource_group=rg.name, location=location,
                                                       public_ip_allocation_method="Dynamic")
        else:
            public_ip = self.ssh.driver.ex_list_public_ips(resource_group=rg.name)[0]  # PPR: pourquoi la première ?

        # Network Interface
        if not self.ssh.driver.ex_list_nics(resource_group=rg.name):
            if not self.ssh.driver.ex_list_subnets(vn):
                logging.warning("You must create a Subnet in Virtual Network : " + vn.name)
                return 1
            else:
                sn = self.ssh.driver.ex_list_subnets(vn)[0]
            ni = self.ssh.driver.ex_create_network_interface(name="sshcrosscloud-ni", resource_group=rg.name,
                                                        location=location, public_ip=public_ip, subnet=sn)
        else:
            ni = self.ssh.driver.ex_list_nics(resource_group=rg.name)[0]

        # Node Creation
        node = self.ssh.driver.create_node(name=self.ssh.env['INSTANCE_NAME'],
                                      image=image,
                                      size=size,
                                      ex_user_name=self.ssh.env['INSTANCE_USER'],
                                      auth=auth,
                                      ex_resource_group=rg.name,
                                      ex_network=vn.name,
                                      ex_use_managed_disks=True,
                                      ex_nic=ni,
                                      location=location,
                                      ex_storage_account="useless"  # this argument is useless, but libcloud requires it
                                      )

        return node


class SpecificGPC(ProviderSpecific):
    def __init__(self, ssh):
        self.ssh = ssh

    def create_instance(self):
        # Location
        locations = self.ssh.driver.list_locations()
        location = [l for l in locations if self.ssh.env['REGION'] in l.name][0]

        # Image
        images = self.ssh.driver.list_images()
        image = [i for i in images if self.ssh.env['IMAGE_NAME'] in i.name][0]

        # Size
        sizes = self.ssh.driver.list_sizes()
        size = [s for s in sizes if self.ssh.env["INSTANCE_TYPE"] in s.name][0]

        # Metadata (ssh-key)
        metadata = {
            "items": [
                {
                    "key": "ssh-keys",
                    "value": "antoinebourayne:" + get_public_key(self.ssh.env['USERNAME'])
                }
            ]
        }

        # Node Creation
        node = self.ssh.driver.create_node(name=self.ssh.env['INSTANCE_NAME'],
                                      image=image,
                                      size=size,
                                      ex_metadata=metadata)

        return node


def get_provider_specific(ssh: SSHCrossCloud):
    if ssh.env['PROVIDER'] == 'AWS':
        return SpecificAWS(ssh)

    if ssh.env['PROVIDER'] == 'AZURE':
        return SpecificAzure(ssh)

    if ssh.env['PROVIDER'] == 'GCP':
        return SpecificGPC(ssh)



