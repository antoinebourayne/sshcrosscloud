import os
import getpass as gt
import sys
from pathlib import Path
import socket
import configparser
import getpass
from dotenv import find_dotenv, dotenv_values
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
import logging

from sshcrosscloud.utils import get_string_from_file

_global_dict = {
    'DISABLE_HOST_CHECKING': "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=quiet",
    'FINAL_STATE': 'terminate'
}

_aws_default_dict = {
    'REGION': "eu-central-1",
    'INSTANCE_TYPE': "t2.micro",
    'USER_DATA': "",
    'SECURITY_GROUP': "sshcrosscloud",
    'IMAGE_ID': "ami-0e342d72b12109f91",
    'IMAGE_NAME': "ubuntu"
}

_azure_default_dict = {
    'REGION': "westus",
    'INSTANCE_TYPE': "Standard_B1ls",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
    'IMAGE_ID': "UbuntuServer:16.04",
    'AZ_RESOURCE_GROUP': "NetworkWatcherRG",
    'AZ_PUBLISHER': "Canonical",
}

_gcp_default_dict = {
    'REGION': "us-central1-a",
    'INSTANCE_TYPE': "f1-micro",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
}


class SSHCrossCloud:
    nbOfSshConnections = 0

    def __init__(self, pre_env, param_list: dict):
        # Check that the parameters have only one action and one final state
        self._check_parameters(param_list)

        # By default is default
        self.default_dict = _global_dict
        self._init_env(pre_env)
        self._init_variables()

        # Credentials and provider specifics
        self._init_provider_specifics()

        # Driver can be instantiated only after getting credentials
        self._init_driver()

        # These variables can only be set after the driver set
        self._init_instance_attributes_from_name()

    def _init_env(self, pre_env):
        """
        A la fin de la fonction, env possède les valeurs mélangées de
        default, puis .env, puis environ.
        """
        if pre_env['PROVIDER'] == 'AWS':
            self.default_dict.update(_aws_default_dict)
        elif pre_env['PROVIDER'] == 'AZURE':
            self.default_dict.update(_azure_default_dict)
        elif pre_env['PROVIDER'] == 'GCP':
            self.default_dict.update(_gcp_default_dict)
        else:
            logging.warning("Provider not supported")
            return 1
        # dotenv values are taken form .env file
        dotenv = dotenv_values(find_dotenv())
        self.env = self.create_context(self.default_dict, dotenv, os.environ)

    def get_instance_user(self):
        if self.env['PROVIDER'] == "AWS":
            default_user_list = {
                'Amazon Linux': 'ec2-user',
                'ubuntu': 'ubuntu',
                'RHEL 6.[0-3]': 'root',
                'RHEL 6.[0-9]+': 'ec2-user',
                'Fedora': 'fedora',
                'Centos': 'centos',
                'SUSE': 'ec2-user',
                'BitNami': 'bitnami',
                'TurnKey': 'root',
                'NanoStack': 'ubuntu',
                'FreeBSD': 'ec2-user',
                'OmniOS': 'root',
            }
            for i, j in default_user_list.items():
                if i.lower() in self.env['IMAGE_NAME'].lower():
                    return j
        if self.env['PROVIDER'] == "AZURE":
            return "azure"
        if self.env['PROVIDER'] == "GCP":
            return getpass.getuser()

    # Initialization methods
    def create_context(self, defaultenv, dotenv, basenv):
        """

        :param defaultenv:
        :param dotenv:
        :param basenv:
        :return:
        """
        env = defaultenv.copy()

        for k, v in dotenv.items():
            env[k] = v

        for k, v in basenv.items():
            env[k] = v

        return env

    def _init_variables(
            self):  # En faire une vrai méthode (avec un self en premier paramètre), soit en faire un function, qui recoit en env en paramètre.
        """
        A la fin de la fonction, env possède le maximum de variables d'environement
        calculés, pour ne plus avoir à gérer les erreurs ou les valeurs par défaut.
        """
        self.env['PROJECT_NAME'] = os.path.basename(os.getcwd())
        # Specific to entreprise polygrams
        if not self.env.get("POLYGRAM"):
            self.env["USERNAME"] = gt.getuser()
        else:
            self.env["USERNAME"] = self.env["POLYGRAM"]
        if not self.env.get('AWS_KEY_NAME'):
            self.env['AWS_KEY_NAME'] = self.env['USERNAME']
        if not self.env.get('INSTANCE_NAME'):
            self.env['INSTANCE_NAME'] = self.env['AWS_KEY_NAME'].lower() + "-" + self.env['PROJECT_NAME']
        if not self.env.get('AWS_RSYNC_DIR'):
            self.env['AWS_RSYNC_DIR'] = os.getcwd()
        if not self.env.get("REGION"):
            self.env["REGION"] = get_region()
        if not self.env.get('PEM_SSH'):
            self.env['PEM_SSH'] = "-i " + str(Path.home()) + "/.ssh/" + self.env['USERNAME']

        if 'DEBUG' in self.env:
            if self.env['DEBUG'] == "y":
                self.env["FINAL_STATE"] = "leave"

        self.env['OS_NAME'] = os.name
        self.env['USER_DATA'] = get_string_from_file(".user_data")
        self.env['INSTANCE_USER'] = self.get_instance_user()

        tags = {
            'Name': self.env['INSTANCE_NAME'],
            'User': gt.getuser(),
            'Hostname': socket.gethostname(),
            'Username': self.env['USERNAME']
        }

        self.env['AWS_TAGS'] = "[" + str(tags) + "]"

    def _init_provider_specifics(self):
        if self.env['PROVIDER'] == "AWS":
            self.env['AWS_ACCESS_KEY_ID'], self.env['AWS_SECRET_ACCESS_KEY'] = get_aws_credentials(self)
        elif self.env['PROVIDER'] == "AZURE":
            self.env['AZURE_TENANT_ID'], self.env['AZURE_SUBSCRIPTION_ID'], self.env['AZURE_APPLICATION_ID'], self.env[
                'AZURE_SECRET'] = get_azure_credentials(self)
            if not self.env.get("AZ_PUBLIC_IP_NAME"):
                self.env['AZ_PUBLIC_IP_NAME'] = "sshcrosscloud-ip-" + self.env['USERNAME']
            if not self.env.get("AZ_VIRTUAL_NETWORK"):
                self.env['AZ_VIRTUAL_NETWORK'] = "sshcrosscloud-vn-" + self.env['USERNAME']
            if not self.env.get("AZ_SUBNET"):
                self.env['AZ_SUBNET'] = "sshcrosscloud-sn-" + self.env['USERNAME']
        elif self.env['PROVIDER'] == "GCP":
            self.env['GCP_USER_ID'], self.env['GCP_KEY_PATH'], self.env['GCP_PROJECT'], self.env[
                'GCP_DATA_CENTER'] = get_gcp_credentials(self)
        else:
            logging.info("Provider not supported")

    def _check_parameters(self, param_list):
        list_final_state = (param_list['leave'], param_list['stop'], param_list['terminate'])
        if sum(list_final_state) > 1:
            raise Exception("Can't have multiple final states")
        list_actions = (param_list['detach'], param_list['attach'], param_list['finish'])
        if sum(list_actions) > 1:
            raise Exception("Can't have multiple actions")
        return 0

    def _init_instance_attributes_from_name(self):
        if self.env['PROVIDER'] == "AZURE":
            nodes = self.driver.list_nodes(self.env['AZ_RESOURCE_GROUP'])
        else:
            nodes = self.driver.list_nodes()
        for node in nodes:
            if node.name == self.env['INSTANCE_NAME'] and node.state not in ["terminated"]:
                self.env['INSTANCE_ID'] = node.id
                self.env['INSTANCE_STATE'] = node.state
                if node.state == "running":
                    self.env['PUBLIC_IP'] = node.public_ips[0]

    def _init_driver(self):
        """
        AWS EC2  : AWS
        Azure VM : AZURE
        Google Compute Engine : GCP
        :param env:
        :return: 0 if ok 1 if error
        """
        try:
            if self.env["PROVIDER"] == "AWS":
                # TODO base config driver, EC2config en hérite
                # creer une classe ConfigDriver (base des config drivers)
                # creer une classe Ec2configdriver qui hérite de ConfigDriver + azure etc
                # creer une fonction get_config_driver qui recoit comme param un provider, et un provider classique
                # getprovider et getconfigprovider ont le meme param
                #
                cls = get_driver(Provider.EC2)
                provider_driver = cls(self.env["AWS_ACCESS_KEY_ID"],
                                      self.env["AWS_SECRET_ACCESS_KEY"],
                                      region=self.env["REGION"])
                print(provider_driver.create_key_pair("keytest").__dict__)
            elif self.env["PROVIDER"] == "AZURE":
                cls = get_driver(Provider.AZURE_ARM)
                provider_driver = cls(tenant_id=self.env["AZURE_TENANT_ID"],
                                      subscription_id=self.env["AZURE_SUBSCRIPTION_ID"],
                                      key=self.env["AZURE_APPLICATION_ID"],
                                      secret=self.env["AZURE_SECRET"])
            elif self.env["PROVIDER"] == "GCP":
                cls = get_driver(Provider.GCE)
                provider_driver = cls(user_id=self.env['GCP_USER_ID'],
                                      key=self.env['GCP_KEY_PATH'],
                                      project=self.env['GCP_PROJECT'],
                                      datacenter=self.env['GCP_DATA_CENTER'])
            else:
                logging.info("Provider not supported")
                return 1

            self.driver = provider_driver

        except:
            raise Exception("Could not get driver")


def get_aws_credentials(ssh: SSHCrossCloud):
    if os.path.isfile(str(Path.home()) + "/.aws/credentials"):

        config = configparser.ConfigParser()
        config.read(str(Path.home()) + "/.aws/credentials")
        aws_access_key_id = config['default']['aws_access_key_id']
        aws_secret_access_key = config['default']['aws_secret_access_key']

        return aws_access_key_id, aws_secret_access_key
    else:
        logging.warning("No credentials found in " + str(Path.home()) + "/.aws/credentials")
        logging.info(
            "Please run 'sshcrosscloud --config --provider " + ssh.env['PROVIDER'] + "' to configure credentials")
        return 1


def get_azure_credentials(ssh: SSHCrossCloud):
    if os.path.isfile(str(Path.home()) + "/.azure/credentials"):

        config = configparser.ConfigParser()
        config.read(str(Path.home()) + "/.azure/credentials")
        tenant_id = config['default']['tenant']
        subscription_id = config['default']['subscription_id']
        client_id = config['default']['client_id']
        secret = config['default']['secret']

        return tenant_id, subscription_id, client_id, secret
    else:
        logging.warning("No credentials found in " + str(Path.home()) + "/.azure/credentials")
        logging.info(
            "Please run 'sshcrosscloud --config --provider " + ssh.env['PROVIDER'] + "' to configure credentials")
        return 1


def get_gcp_credentials(ssh: SSHCrossCloud):
    if os.path.isfile(str(Path.home()) + "/.gcp/credentials"):

        config = configparser.ConfigParser()
        config.read(str(Path.home()) + "/.gcp/credentials")
        user_id = config['default']['user_id']
        key = config['default']['key']
        project = config['default']['project']
        datacenter = config['default']['datacenter']

        return user_id, key, project, datacenter
    else:
        logging.warning("No credentials found in " + str(Path.home()) + "/.gcp/credentials")
        logging.info(
            "Please run 'sshcrosscloud --config --provider " + ssh.env['PROVIDER'] + "' to configure credentials")
        return 1


def get_azure_resource_group(ssh: SSHCrossCloud):
    if not ssh.driver.ex_list_resource_groups():
        logging.warning("No Resource Group found, you must create one")
        logging.info("You can run 'az group create -l <REGION> -n <NAME>' or create one on https://portal.azure.com/")
        return 1
    else:
        rg = ssh.driver.ex_list_resource_groups()[0]
        return rg


def get_region():
    # TODO: s'occuper des autres providers
    with open(str(Path.home()) + ".aws/config", 'r') as file:
        data = file.read().replace('\n', '')
        region = data.split("region = ", 1)[1]
        return region
