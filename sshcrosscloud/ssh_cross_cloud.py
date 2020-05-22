import os
import getpass as gt
from pathlib import Path
import socket
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
    'REGION': "us-central1-a",
    'INSTANCE_TYPE': "f1-micro",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
    'IMAGE_ID': "UbuntuServer:16.04",
    'AZ_RESOURCE_GROUP': "NetworkWatcherRG",
}

_gcp_default_dict = {
    'REGION': "us-central1-a",
    'INSTANCE_TYPE': "f1-micro",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
}

# PPR idee pour le contructeur avec les paramètres in input.
# Cela permet de tester la classe dans tous les scénarios
# SSHCrossCloud(["--attach","--finish"])

# SshDataScience object contains and initializes the variables
# Tous les appels avec un self doivent devenir des méthdes

class SSHCrossCloud:
    nbOfSshConnections = 0

    def __init__(self, pre_env):  # PPR : dans ce cas, ajouter un paramètre array avec la ligne de commande et l'environ
        # By default is default
        self.default_dict = _global_dict
        self._set_env(pre_env)
        self.env = init_variables(self)  # PPR : soit egale pour les 2, soit effet de bord pour les deux.
        # PPR: autre approche, avec le mode return env, pourvoir faire un self.env = init_variable(self,self.init_env())
        # PPR: choisir en méthode ou fonction pour les deux appels

        # Credentials and provider specifics
        set_provider_specifics(self)  # PPR: idem. Function ou method ?

        # Driver can be instantiated only after getting credentials
        self.driver = create_driver(self)

        # These variables can only be set after the driver set
        self.env['INSTANCE_ID'] = get_instance_id_from_name(self)
        self.env['PUBLIC_IP'] = get_public_ip(self)

    def _set_env(self, pre_env):  # PPR devrait être privé. renommer init_env et recevoir le envion en paramètre
        """
        A la fin de la fonction, env possède les valeurs mélangées de
        default, puis .env, puis environ.
        """
        if pre_env['PROVIDER'] == 'AWS':  # PPR : impossible de tester. La classe ne doit pas avoir de dépendences à os.environ
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
        self.env = self.replace_default_env(self.default_dict, dotenv, os.environ)

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
    def replace_default_env(self, defaultenv, dotenv,
                            basenv):  # PPR le nom doit être create_context() et non replace_default_env
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


def init_variables(
        ssh: SSHCrossCloud):  # En faire une vrai méthode (avec un self en premier paramètre), soit en faire un function, qui recoit en env en paramètre.
    """
    A la fin de la fonction, env possède le maximum de variables d'environement
    calculés, pour ne plus avoir à gérer les erreurs ou les valeurs par défaut.
    """
    ssh.env['PROJECT_NAME'] = os.path.basename(os.getcwd())
    # Specific to entreprise polygrams
    if not ssh.env.get("POLYGRAM"):
        ssh.env["USERNAME"] = gt.getuser()
    else:
        ssh.env["USERNAME"] = ssh.env["POLYGRAM"]
    if not ssh.env.get('AWS_KEY_NAME'):
        ssh.env['AWS_KEY_NAME'] = ssh.env['USERNAME']
    if not ssh.env.get('INSTANCE_NAME'):
        ssh.env['INSTANCE_NAME'] = ssh.env['AWS_KEY_NAME'].lower() + "-" + ssh.env['PROJECT_NAME']
    if not ssh.env.get('AWS_RSYNC_DIR'):
        ssh.env['AWS_RSYNC_DIR'] = os.getcwd()
    if not ssh.env.get("REGION"):
        ssh.env["REGION"] = get_region()
    if not ssh.env.get('PEM_SSH'):
        ssh.env['PEM_SSH'] = "-i " + str(Path.home()) + "/.ssh/" + ssh.env['USERNAME']

    if 'DEBUG' in ssh.env:
        if ssh.env['DEBUG'] == "y":
            ssh.env["FINAL_STATE"] = "leave"

    ssh.env['OS_NAME'] = os.name
    ssh.env['USER_DATA'] = get_string_from_file(".user_data")
    ssh.env['INSTANCE_USER'] = ssh.get_instance_user()

    tags = {
        'Name': ssh.env['INSTANCE_NAME'],
        'User': gt.getuser(),
        'Hostname': socket.gethostname(),
        'Username': ssh.env['USERNAME']
    }

    ssh.env['AWS_TAGS'] = "[" + str(tags) + "]"

    return ssh.env


def set_provider_specifics(ssh: SSHCrossCloud):
    if ssh.env['PROVIDER'] == "AWS":
        ssh.env['AWS_ACCESS_KEY_ID'], ssh.env['AWS_SECRET_ACCESS_KEY'] = get_aws_credentials(ssh)
    elif ssh.env['PROVIDER'] == "AZURE":
        ssh.env['AZURE_TENANT_ID'], ssh.env['AZURE_SUBSCRIPTION_ID'], ssh.env['AZURE_APPLICATION_ID'], ssh.env[
            'AZURE_SECRET'] = get_azure_credentials(ssh)
    elif ssh.env['PROVIDER'] == "GCP":
        ssh.env['GCP_USER_ID'], ssh.env['GCP_KEY_PATH'], ssh.env['GCP_PROJECT'], ssh.env[
            'GCP_DATA_CENTER'] = get_gcp_credentials(ssh)
    else:
        logging.info("Provider not supported")


def create_driver(ssh: SSHCrossCloud):
    """
    AWS EC2  : AWS
    Azure VM : AZURE
    Google Compute Engine : GCP
    :param env:
    :return: 0 if ok 1 if error
    """
    try:
        if ssh.env["PROVIDER"] == "AWS":
            # TODO base config driver, EC2config en hérite
            # creer une classe ConfigDriver (base des config drivers)
            # creer une classe Ec2configdriver qui hérite de ConfigDriver + azure etc
            # creer une fonction get_config_driver qui recoit comme param un provider, et un provider classique
            # getprovider et getconfigprovider ont le meme param
            #
            cls = get_driver(Provider.EC2)
            driver = cls(ssh.env["AWS_ACCESS_KEY_ID"],
                         ssh.env["AWS_SECRET_ACCESS_KEY"],
                         region=ssh.env["REGION"])
        elif ssh.env["PROVIDER"] == "AZURE":
            cls = get_driver(Provider.AZURE_ARM)
            driver = cls(tenant_id=ssh.env["AZURE_TENANT_ID"],
                         subscription_id=ssh.env["AZURE_SUBSCRIPTION_ID"],
                         key=ssh.env["AZURE_APPLICATION_ID"],
                         secret=ssh.env["AZURE_SECRET"])
        elif ssh.env["PROVIDER"] == "GCP":
            cls = get_driver(Provider.GCE)
            driver = cls(user_id=ssh.env['GCP_USER_ID'],
                         key=ssh.env['GCP_KEY_PATH'],
                         project=ssh.env['GCP_PROJECT'],
                         datacenter=ssh.env['GCP_DATA_CENTER'])
        else:
            logging.info("Provider not supported")
            return 1

        return driver

    except:
        logging.warning("Could not get driver")
        return 1


# PPR: return None ?
def get_instance_id_from_name(ssh: SSHCrossCloud):  # PPR: retourner id et ip en même temps
    if ssh.env['PROVIDER'] == "AZURE":
        nodes = ssh.driver.list_nodes(ssh.env['AZ_RESOURCE_GROUP'])
    else:
        nodes = ssh.driver.list_nodes()
    for node in nodes:
        if node.name == ssh.env['INSTANCE_NAME'] and node.state not in ["terminated", "unknown"]:
            return node.id


# PPR trouver un vrai parseur de fichier
# ou l'écrire en iterant ligne par ligne, en supprimant les lignes avec commentaire,
# par ligne, en split sur le '=', pour identifier la clé et la valeur
# et ajuster la récupération des datas au fur et à mesure.
# Le code doit être capable de gérer les cas suivants:
# un commentaire avec la clé aws_access_key_id
# Plusieurs lignes avec aws_access_key_id
# Lignes dans un autre ordre,
# etc.
def get_aws_credentials(ssh: SSHCrossCloud):
    if os.path.isfile(str(Path.home()) + "/.aws/credentials"):
        with open(str(Path.home()) + "/.aws/credentials", 'r') as file:
            data = file.read()
            aws_access_key_id = (data.split('aws_access_key_id='))[1].split('\n')[0]
            aws_secret_access_key = (data.split('aws_secret_access_key='))[1].split('\n')[0]

            return aws_access_key_id, aws_secret_access_key
    else:
        logging.warning("No credentials found in " + str(Path.home()) + "/.aws/credentials")
        logging.info(
            "Please run 'sshcrosscloud --config --provider " + ssh.env['PROVIDER'] + "' to configure credentials")
        return 1


def get_azure_credentials(
        ssh: SSHCrossCloud):  # PPR: s'assurer qu'il n'est pas possible de récuperer ces infos avec libcloud
    if os.path.isfile(str(Path.home()) + "/.azure/credentials.txt"):
        with open(str(Path.home()) + "/.azure/credentials.txt", 'r') as file:
            data = file.read()
            tenant_id = (data.split('tenant='))[1].split('\n')[0]
            subscription_id = (data.split('subscription_id='))[1].split('\n')[0]
            client_id = (data.split('client_id='))[1].split('\n')[0]
            secret = (data.split('secret='))[1].split('\n')[0]

            return tenant_id, subscription_id, client_id, secret
    else:
        logging.warning("No credentials found in " + str(Path.home()) + "/.azure/credentials.txt")
        logging.info(
            "Please run 'sshcrosscloud --config --provider " + ssh.env['PROVIDER'] + "' to configure credentials")
        return 1


def get_gcp_credentials(ssh: SSHCrossCloud):
    if os.path.isfile(str(Path.home()) + "/.gcp/credentials.txt"):
        with open(str(Path.home()) + "/.gcp/credentials.txt", 'r') as file:
            data = file.read()
            user_id = (data.split('user_id='))[1].split('\n')[0]
            key = (data.split('key='))[1].split('\n')[0]
            project = (data.split('project='))[1].split('\n')[0]
            datacenter = (data.split('datacenter='))[1].split('\n')[0]

            return user_id, key, project, datacenter
    else:
        logging.warning("No credentials found in " + str(Path.home()) + "/.gcp/credentials.txt")
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


def get_public_ip(ssh: SSHCrossCloud):  # PPR: a virer (voir get_instance_id_from_name)
    if ssh.env['PROVIDER'] == "AZURE":
        nodes = ssh.driver.list_nodes(ssh.env['AZ_RESOURCE_GROUP'])
    else:
        nodes = ssh.driver.list_nodes()
    if ssh.env.get('INSTANCE_ID'):
        for node in nodes:
            if node.id == ssh.env['INSTANCE_ID'] and node.state == "running":
                public_ip = node.public_ips[0]
                return public_ip


def get_region():
    # TODO: s'occuper des autres providers
    with open(str(Path.home()) + ".aws/config", 'r') as file:
        data = file.read().replace('\n', '')
        region = data.split("region = ", 1)[1]
        return region
