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

from sshcrosscloud import utils
from sshcrosscloud.utils import get_string_from_file

"""
SSHCrossCloud Class

Basically contains all the attributes to create an instance on multiple providers and a Libcloud Driver
"""


class SSHCrossCloud:
    nbOfSshConnections = 0

    def __init__(self, pre_env, param_dict: dict):
        # Init variables
        self.pre_env = pre_env
        self.param_dict = param_dict
        self.default_dict = utils.global_dict

        # Check that the parameters have only one action and one final state
        self._check_parameters()

        # dotenv values are taken form .env file
        self._init_env(dotenv_values(find_dotenv()), os.environ)
        self._init_variables()

        # Credentials and provider specifics
        self._init_provider_specifics()

        # Credentials
        self._init_credentials_path()

        # Driver can be instantiated only after getting credentials
        self._init_driver()

        # These variables can only be set after the driver set
        self._init_instance_attributes_from_name()

    def _init_env(self, dotenv, environ):
        """
        A la fin de la fonction, env possède les valeurs mélangées de
        default, puis .env, puis environ.
        """
        if self.pre_env['PROVIDER'] == 'AWS':
            self.default_dict.update(utils.aws_default_dict)
        elif self.pre_env['PROVIDER'] == 'AZURE':
            self.default_dict.update(utils.azure_default_dict)
        elif self.pre_env['PROVIDER'] == 'GCP':
            self.default_dict.update(utils.gcp_default_dict)
        else:
            raise Exception(logging.warning("Provider not supported"))

        # Default
        env = self.default_dict.copy()

        # Dotenv
        for k, v in dotenv.items():
            env[k] = v

        # OS Environ
        for k, v in environ.items():
            env[k] = v

        self.env = env

    def _init_variables(self):
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
        if not self.env.get('PEM_SSH'):
            self.env['PEM_SSH'] = "-i " + str(Path.home()) + "/.ssh/" + self.env['USERNAME']

        if 'DEBUG' in self.env:
            if self.env['DEBUG'] == "y":
                self.env["FINAL_STATE"] = "leave"

        self.env['OS_NAME'] = os.name
        self.env['USER_DATA'] = get_string_from_file(".user_data")
        self.env['INSTANCE_USER'] = get_instance_user(self.env['PROVIDER'])

        tags = {
            'Name': self.env['INSTANCE_NAME'],
            'User': gt.getuser(),
            'Hostname': socket.gethostname(),
            'Username': self.env['USERNAME']
        }

        self.env['AWS_TAGS'] = "[" + str(tags) + "]"

    def _init_provider_specifics(self):
        if self.env['PROVIDER'] == "AWS":
            if not self.env.get("REGION"):
                self.env["REGION"] = get_aws_region(self.env['AWS_FILE_PATH'])
            self.env['AWS_ACCESS_KEY_ID'], self.env['AWS_SECRET_ACCESS_KEY'] = get_credentials(
                self.env['AWS_FILE_PATH'], self.env['PROVIDER'])

        elif self.env['PROVIDER'] == "AZURE":
            if not self.env.get("REGION"):
                raise Exception("No region found, you must specify a region in .env file")
            self.env['AZURE_TENANT_ID'], self.env['AZURE_SUBSCRIPTION_ID'], self.env['AZURE_APPLICATION_ID'], self.env[
                'AZURE_SECRET'] = get_credentials(
                self.env['AZURE_FILE_PATH'], self.env['PROVIDER'])
            if not self.env.get("AZ_PUBLIC_IP_NAME"):
                self.env['AZ_PUBLIC_IP_NAME'] = "sshcrosscloud-ip-" + self.env['USERNAME']
            if not self.env.get("AZ_VIRTUAL_NETWORK"):
                self.env['AZ_VIRTUAL_NETWORK'] = "sshcrosscloud-vn-" + self.env['USERNAME']
            if not self.env.get("AZ_SUBNET"):
                self.env['AZ_SUBNET'] = "sshcrosscloud-sn-" + self.env['USERNAME']

        elif self.env['PROVIDER'] == "GCP":
            if not self.env.get("REGION"):
                raise Exception("No region found, you must specify a region in .env file")
            self.env['GCP_USER_ID'], self.env['GCP_KEY_PATH'], self.env['GCP_PROJECT'], self.env[
                'GCP_DATA_CENTER'] = get_credentials(

                self.env['GCP_FILE_PATH'], self.env['PROVIDER'])
        else:
            logging.info("Provider not supported")

    def _check_parameters(self):
        if not self.param_dict.get('provider'):
            raise Exception("You must chose a provider (aws, azure or gcp)")
        list_final_state = (self.param_dict['leave'], self.param_dict['stop'], self.param_dict['terminate'])
        if sum(list_final_state) > 1:
            raise Exception("Can't have multiple final states")
        list_actions = (self.param_dict['detach'], self.param_dict['attach'], self.param_dict['finish'])
        if sum(list_actions) > 1:
            raise Exception("Can't have multiple actions")

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

    def _init_credentials_path(self):
        """
        Creates credentials
        :param self:
        :return: the path of the file where the credentials are stored
        """
        # TODO: GCP has another method for credentials, what to do ?
        if self.env.get('CONFIG'):
            default_credentials_path = self.env['PROVIDER_FILE_PATH']
            if os.path.isfile(default_credentials_path):
                with open(default_credentials_path, 'r+') as file:
                    file_data = file.read()
                    if file_data:
                        logging.info("Credentials have already been saved, would you like to change them? y/n")
                        answer = input()
                        if answer == 'y':
                            pass
                        else:
                            logging.info("Credentials have not been changed")
                            self.env['PROVIDER_FILE_PATH'] = default_credentials_path
                write_credentials(default_credentials_path, self.pre_env['PROVIDER'])
                self.env['PROVIDER_FILE_PATH'] = default_credentials_path
            else:
                logging.warning("AWS Credentials file does not exist, create one (1) "
                                "or give path to another credential file (2) ? ")
                answer = input()
                if answer == '1':
                    write_credentials(default_credentials_path, self.pre_env['PROVIDER'])
                    self.env['PROVIDER_FILE_PATH'] = default_credentials_path
                elif answer == '2':
                    logging.info("Enter the path to your credentials file: (ex :/path/to/your/file/.aws)")
                    custom_credentials_path = input()
                    write_credentials(custom_credentials_path, self.pre_env['PROVIDER'])
                    self.env['PROVIDER_FILE_PATH'] = custom_credentials_path
                else:
                    raise Exception("You need a credentials file to create an instance")


def get_instance_user(provider: str):
    if provider == "AWS":
        default_user_list = utils.aws_default_user_list
        for i, j in default_user_list.items():
            if i.lower() in provider.lower():
                return j
    if provider == "AZURE":
        return "azure"
    if provider == "GCP":
        return getpass.getuser()


def get_aws_region(path: str):
    if os.path.isfile(path):

        config = configparser.ConfigParser()
        config.read(path)
        aws_region = config['default']['region']

        return aws_region
    else:
        raise Exception("No region found in " + path + ", run sshcrosscloud --config -- provider aws")


def get_credentials(path: str, provider: str):
    if provider == 'AWS':
        credentials_path = path + "/credentials"
        if os.path.isfile(credentials_path):

            config = configparser.ConfigParser()
            config.read(credentials_path)
            aws_access_key_id = config['default']['aws_access_key_id']
            aws_secret_access_key = config['default']['aws_secret_access_key']

            return aws_access_key_id, aws_secret_access_key
        else:
            raise Exception("No credentials found in " + credentials_path +
                            ", run sshcrosscloud --config -- provider aws")

    elif provider == 'AZURE':
        credentials_path = path + "/credentials"
        if os.path.isfile(credentials_path):

            config = configparser.ConfigParser()
            config.read(credentials_path)
            tenant_id = config['default']['tenant']
            subscription_id = config['default']['subscription_id']
            client_id = config['default']['client_id']
            secret = config['default']['secret']

            return tenant_id, subscription_id, client_id, secret
        else:
            raise Exception("No credentials found in " + credentials_path + ", run sshcrosscloud --config -- provider azure")

    elif provider == 'GCP':
        # TODO: different methods : json https://cloud.google.com/docs/authentication/production?hl=fr#auth-cloud-explicit-python
        credentials_path = path + "/credentials"
        if os.path.isfile(credentials_path):

            config = configparser.ConfigParser()
            config.read(credentials_path)
            user_id = config['default']['user_id']
            key = config['default']['key']
            project = config['default']['project']
            datacenter = config['default']['datacenter']

            return user_id, key, project, datacenter
        else:
            raise Exception("No credentials found in " + credentials_path + ", run sshcrosscloud --config -- provider gcp")

    else:
        raise Exception("Provider not supported")


def write_credentials(path: str, provider: str):
    if provider == 'AWS':
        with open(path, 'w') as cred_file:
            logging.info("Enter AWS ACCESS KEY ID:")
            aws_access_key_id = input()
            logging.info("Enter AWS SECRET ACCESS ID:")
            aws_secret_access_key = input()
            logging.info("Enter REGION:")
            aws_region = input()

            config = configparser.ConfigParser()
            config['default'] = {'aws_access_key_id': aws_access_key_id,
                                 'aws_secret_access_key': aws_secret_access_key,
                                 'region': aws_region}

            config.write(cred_file)
            logging.info("Credentials have been saved")

    elif provider == 'AZURE':
        with open(path, 'w') as cred_file:
            logging.info("Enter AZURE Tenant:")
            tenant = input()
            logging.info("Enter AZURE Subscription ID:")
            subscription_id = input()
            logging.info("Enter AZURE Client ID:")
            client_id = input()
            logging.info("Enter AZURE Secret:")
            secret = input()
            config = configparser.ConfigParser()
            config['default'] = {'tenant': tenant,
                                 'subscription_id': subscription_id,
                                 'client_id': client_id,
                                 'secret': secret}

            config.write(cred_file)
            logging.info("Credentials have been saved")

    elif provider == 'GCP':
        with open(path, 'w') as cred_file:
            logging.info("Enter GCP User ID:")
            user_id = input()
            logging.info("Enter GCP Key ID:")
            key = input()
            logging.info("Enter GCP Project ID:")
            project = input()
            logging.info("Enter GCP Datacenter ID:")
            datacenter = input()

            config = configparser.ConfigParser()
            config['default'] = {'user_id': user_id,
                                 'key': key,
                                 'project': project,
                                 'datacenter': datacenter}

            config.write(cred_file)
            logging.info("Credentials have been saved")
