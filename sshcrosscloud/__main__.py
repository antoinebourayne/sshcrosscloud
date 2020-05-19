import getpass
import getpass as gt
import subprocess
import time
import logging
from pathlib import Path
from os import environ
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from libcloud.compute.base import NodeAuthSSHKey
from dotenv import find_dotenv, dotenv_values
import os
import socket
import sys
from libcloud_extended.configure import ec2configure
from argparse import ArgumentParser

"""

SSH-CROSS-CLOUD

"""

global_dict = {
    'DISABLE_HOST_CHECKING': "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=quiet",
    'FINAL_STATE': 'terminate'
}

aws_default_dict = {
    'REGION': "eu-central-1",
    'INSTANCE_TYPE': "t2.micro",
    'USER_DATA': "",
    'SECURITY_GROUP': "ANBO",
    'IMAGE_ID': "ami-0e342d72b12109f91",
    'IMAGE_NAME': "ubuntu"
}

azure_default_dict = {
    'REGION': "us-central1-a",
    'INSTANCE_TYPE': "f1-micro",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
    'IMAGE_ID': "UbuntuServer:16.04",
    'AZ_RESOURCE_GROUP': "NetworkWatcherRG",
}

gcp_default_dict = {
    'REGION': "us-central1-a",
    'INSTANCE_TYPE': "f1-micro",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
}

# TODO: remplir les "help"
parser = ArgumentParser()

# SSH PARAMETERS
parser.add_argument('sshscript', type=str, nargs='?', help='Code to be executed on the instance')

# FLAGS
parser.add_argument('--leave', action='store_true')
parser.add_argument('--stop', action='store_true')
parser.add_argument('--terminate', action='store_true')
parser.add_argument('--finish', action='store_true')
parser.add_argument('--detach', action='store_true')
parser.add_argument('--attach', action='store_true')
parser.add_argument('--verbose', action='store_true')
parser.add_argument('--status', action='store_true')
parser.add_argument('--destroy', action='store_true')
parser.add_argument('--norsync', action='store_true')
parser.add_argument('--debug', action='store_true')
parser.add_argument('--config', action='store_true')
# VALUES
parser.add_argument('--provider', default=None, const=None)
parser.add_argument('-L', default=None, const=None)
parser.add_argument('-R', default=None, const=None)
parser.add_argument('-i', default=None, const=None)

args = parser.parse_args()


# MAIN
def main():
    # Logs settings
    logging.getLogger().setLevel(logging.INFO)

    # SSH Script
    if parser.parse_args().sshscript:
        os.environ["SSH_SCRIPT"] = parser.parse_args().sshscript

    # Arguments
    if parser.parse_args().leave:
        arg_leave()

    if parser.parse_args().stop:
        arg_stop()

    if parser.parse_args().terminate:
        arg_terminate()

    if parser.parse_args().detach:
        arg_detach()

    if parser.parse_args().attach:
        arg_attach()

    if parser.parse_args().finish:
        arg_finish()

    if parser.parse_args().verbose:
        arg_verbose()

    if parser.parse_args().norsync:
        arg_no_rsync()

    if parser.parse_args().provider:
        arg_provider(parser.parse_args().provider)
    else:
        logging.warning("You must chose a provider (aws, azure or gcp)")
        sys.exit(0)

    if parser.parse_args().L:
        arg_L(parser.parse_args().L)

    if parser.parse_args().R:
        arg_R(parser.parse_args().R)

    if parser.parse_args().i:
        arg_i(parser.parse_args().i)

    if parser.parse_args().debug:
        arg_debug()

    if parser.parse_args().config:
        arg_config()

    if parser.parse_args().status:
        arg_status()

    if parser.parse_args().destroy:
        arg_destroy()

    """-----------------Here call methods---------------------"""
    logging.info('-----SSH CROSS CLOUD-----')

    # Credentials
    if os.environ.get('CONFIG'):
        set_credentials()

    # SSH Object
    ssh = SSHCrossCloud()

    # Auto config
    if os.environ.get('CONFIG'):
        provider_config(ssh)

    # TODO: gérer les différents displays
    # display_aws_instance_characteristics(ssh)

    # If no instance found, create one
    if not ssh.env.get("INSTANCE_ID"):
        create_instance(ssh)
    else:
        logging.info("An instance is already alive")

    # Try to connect multiple times to the instance to check the connection
    connection_result = wait_until_initialization(ssh)

    if connection_result == 0:
        pass
        # Copy directory from local computer to instance
        rsync_to_instance(ssh)

        # SSH connection to instance
        attach_to_instance(ssh)

        # When done synchronize back to local directory
        rsync_back_to_local(ssh)

        # How to finish process
        finish_action(ssh)

    logging.info('SSH CROSS CLOUD - END')
    """-------------------------------------------------------"""
    return 0


# SshDataScience object contains and initializes the variables
class SSHCrossCloud:
    nbOfSshConnections = 0

    def __init__(self):
        # By default is default
        self.default_dict = global_dict
        self.set_env()
        self.env = init_variables(self)

        # Credentials and provider specifics
        set_provider_specifics(self)

        # Driver can be instantiated only after getting credentials
        self.driver = create_driver(self)

        # These variables can only be set after the driver set
        self.env['INSTANCE_ID'] = get_instance_id_from_name(self)
        self.env['PUBLIC_IP'] = get_public_ip(self)

    def set_env(self):
        """
        A la fin de la fonction, env possède les valeurs mélangées de
        default, puis .env, puis environ.
        """
        if os.environ['PROVIDER'] == 'AWS':
            self.default_dict.update(aws_default_dict)
        elif os.environ['PROVIDER'] == 'AZURE':
            self.default_dict.update(azure_default_dict)
        elif os.environ['PROVIDER'] == 'GCP':
            self.default_dict.update(gcp_default_dict)
        else:
            logging.warning("Provider not supported")
            sys.exit(1)
        # dotenv values are taken form .env file
        dotenv = dotenv_values(find_dotenv())
        self.env = self.replace_default_env(self.default_dict, dotenv, environ)

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
    def replace_default_env(self, defaultenv, dotenv, basenv):
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


# Getters and inits
def get_login() -> str:
    return gt.getuser()


def get_os_name() -> str:
    return os.name


def get_public_key(name: str) -> str:
    try:
        with open(str(Path.home()) + ".ssh/" + name + ".pub", 'r') as file:
            rsa_pub = file.read()
        return rsa_pub
    except:
        logging.info("No key at :" + str(Path.home()) + ".ssh/" + name + + ".pub")


def get_string_from_file(filepath):
    with open(filepath, 'r') as userdatafile:
        return userdatafile.read()


def get_region():
    with open(str(Path.home()) + ".aws/config", 'r') as file:
        data = file.read().replace('\n', '')
        REGION = data.split("region = ", 1)[1]
        return REGION


def set_credentials():
    if os.path.isfile(str(Path.home()) + "/.aws/credentials"):
        with open(str(Path.home()) + "/.aws/credentials", 'r+') as file:
            file_data = file.read()
            if file_data:
                logging.info("Credentials have already been saved, would you like to change them? y/n")
                answer = input()
                if answer == 'y':
                    pass
                else:
                    logging.info("Credentials have not been changed")
                    return 0
        with open(str(Path.home()) + "/.aws/credentials", 'w') as file:
            logging.info("Enter AWS ACCESS KEY ID:")
            aws_access_key_id = input()
            logging.info("Enter AWS SECRET ACCESS ID:")
            aws_secret_access_key = input()
            old_aws_access_key_id = (file_data.split('aws_access_key_id='))[1].split('\n')[0]
            file_data = file_data.replace(old_aws_access_key_id, aws_access_key_id)
            old_aws_secret_access_key = (file_data.split('aws_secret_access_key='))[1].split('\n')[0]
            file_data = file_data.replace(old_aws_secret_access_key, aws_secret_access_key)
            file.write(file_data)
            logging.info("Credentials have been saved")
            return 0
    else:
        logging.warning("AWS Credentials file does not exist")
        return 1


def provider_config(ssh: SSHCrossCloud):
    if ssh.env['PROVIDER'] == 'AWS':
        ec2config = ec2configure.Ec2config(ex_ssh=ssh)

        # SSH Key-Pair
        if ((ssh.env['USERNAME'] in ssh.driver.ex_list_keypairs())
                and (os.path.isfile(str(Path.home()) + "/.ssh" + ssh.env['USERNAME']))):
            logging.info("Key pair already stored, ignoring step")
        else:
            ec2config.create_rsa_key_pair()


def create_driver(ssh: SSHCrossCloud):
    """
    AWS EC2  : AWS
    Azure VM : AZURE
    Google Compute Engine : GCP
    :param env:
    :return:
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
            sys.exit(1)

        return driver
    except:
        logging.warning("Could not get driver")
        sys.exit(1)


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
        sys.exit(1)


def get_azure_credentials(ssh: SSHCrossCloud):
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
        sys.exit(1)


def get_azure_resource_group(ssh: SSHCrossCloud):
    if not ssh.driver.ex_list_resource_groups():
        logging.warning("No Resource Group found, you must create one")
        logging.info("You can run 'az group create -l <REGION> -n <NAME>' or create one on https://portal.azure.com/")
        sys.exit(1)
    else:
        rg = ssh.driver.ex_list_resource_groups()[0]
        return rg


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
        sys.exit(1)


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


def get_instance_id_from_name(ssh: SSHCrossCloud):
    if ssh.env['PROVIDER'] == "AZURE":
        nodes = ssh.driver.list_nodes(ssh.env['AZ_RESOURCE_GROUP'])
    else:
        nodes = ssh.driver.list_nodes()
    for node in nodes:
        if node.name == ssh.env['INSTANCE_NAME'] and node.state not in ["terminated", "unknown"]:
            return node.id


def get_public_ip(ssh: SSHCrossCloud):
    if ssh.env['PROVIDER'] == "AZURE":
        nodes = ssh.driver.list_nodes(ssh.env['AZ_RESOURCE_GROUP'])
    else:
        nodes = ssh.driver.list_nodes()
    if ssh.env.get('INSTANCE_ID'):
        for node in nodes:
            if node.id == ssh.env['INSTANCE_ID'] and node.state == "running":
                public_ip = node.public_ips[0]
                return public_ip


def init_variables(ssh: SSHCrossCloud):
    """
    A la fin de la fonction, env possède le maximum de variables d'environement
    calculés, pour ne plus avoir à gérer les erreurs ou les valeurs par défaut.
    """
    ssh.env['PROJECT_NAME'] = os.path.basename(os.getcwd())
    # Specific to entreprise polygrams
    if not ssh.env.get("POLYGRAM"):
        ssh.env["USERNAME"] = get_login()
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

    ssh.env['OS_NAME'] = get_os_name()
    ssh.env['USER_DATA'] = get_string_from_file(".user_data")
    ssh.env['INSTANCE_USER'] = ssh.get_instance_user()

    tags = {
        'Name': ssh.env['INSTANCE_NAME'],
        'User': get_login(),
        'Hostname': socket.gethostname(),
        'Username': ssh.env['USERNAME']
    }

    ssh.env['AWS_TAGS'] = "[" + str(tags) + "]"

    return ssh.env


def guide_credentials(provider: str):
    if provider == 'AWS':
        guide = """
        To configure AWS credentials, you must follow the instructions below:

        1. You  need to create an AWS account, then IAM console -> Users -> User Actions -> Manage Access Keys -> Create Access Key
        Store this pair of keys in 'HOME/.aws/credentials' as follows:

        [default]
        aws_access_key_id = XXXXXXXXXXXXXXXXXXX
        aws_secret_access_key = XXXXXXXXXXXXXXXXXXX

        2. Execute the following script in a shell (the POLYGRAM will be your signature while managing VMs):

        export POLYGRAM=<myPOLYGRAM>

        3. Execute the following script in a shell (to set the POLYGRAM permanently):

        [ $OSTYPE == 'linux-gnu' ] && RC=~/.bashrc
        [ $OSTYPE == darwin* ] && RC=~/.bash_profile
        [ -e ~/.zshrc ] && RC=~/.zshrc
        echo export POLYGRAM=$POLYGRAM >>${RC} 
        source ${RC}

        4. Create SSH KEY:

        $ ssh-keygen -f ~/.ssh/$POLYGRAM -t rsa -b 4096

        5. Get public key and COPY it: 

        $ ssh-keygen -f ~/.ssh/$POLYGRAM -y

        6. Go to AWS console under Network and Security -> Key Pair and import the public key that you copied and name it like your POLYGRAM      
        """
        logging.info(guide)

    if provider == 'AZURE':
        guide = """
        To configure Azure credentials, you must follow the instructions below:
        (Note that you can configure everything on https://portal.azure.com/)

        1. Create an Application:

        az ad app create --display-name "<Your Application Display Name>" --password <Your_Password>

        2. Create a Service principal

        az ad sp create --id "<Application_Id>"

        3 . Assign roles

        az role assignment create --assignee "<Object_Id>" --role Owner --scope /subscriptions/{subscriptionId}/

        4. Create a file in /HOME/.azure/credentials.txt and store the credentials you created as follows:

        [default]
        subscription_id=XXXXXXXXXXXXXXXXXXX
        client_id=XXXXXXXXXXXXXXXXXXX
        secret=XXXXXXXXXXXXXXXXXXX
        tenant=XXXXXXXXXXXXXXXXXXX

        3. Create a Resource Group:

        az group create -l <myRegion> -n <MyResourceGroup>
        (run 'az account list-locations' if you don't know the regions names)

        4. Create a Virtual Network

        az network vnet create --name <myVirtualNetwork> --resource-group <myResourceGroup> --subnet-name <default>  
        """


def display_aws_instance_characteristics(ssh: SSHCrossCloud):
    logging.info("----------------------------------------------------------")
    logging.info("Provider: " + ssh.env['PROVIDER'])
    logging.info("Instance Name: " + ssh.env['INSTANCE_NAME'])
    logging.info("Region: " + ssh.env['REGION'])
    logging.info("Type: " + ssh.env['INSTANCE_TYPE'])
    logging.info("Image Id: " + ssh.env['IMAGE_ID'])
    logging.info("----------------------------------------------------------")


# Arguments methods
def arg_leave():
    os.environ["FINAL_STATE"] = "leave"


def arg_stop():
    if os.environ.get("SSH_DETACH") != "y" and os.environ.get("SSH_ATTACH") != "y":
        os.environ["FINAL_STATE"] = "stop"


def arg_terminate():
    if os.environ.get("SSH_DETACH") != "y" and os.environ.get("SSH_ATTACH") != "y":
        os.environ["FINAL_STATE"] = "terminate"


def arg_detach():
    os.environ["FINAL_STATE"] = "leave"
    os.environ["SSH_DETACH"] = "y"
    os.environ["MULTIPLEX"] = "y"


def arg_attach():
    os.environ["MULTIPLEX"] = "y"
    os.environ["SSH_ATTACH"] = "y"
    os.environ["FINAL_STATE"] = "leave"
    os.environ["NO_RSYNC_BEGIN"] = "y"
    os.environ["NO_RSYNC_END"] = "y"


def arg_finish():
    os.environ["NO_RSYNC_BEGIN"] = "y"


def arg_config():
    # guide_credentials(os.environ["PROVIDER"])
    os.environ["CONFIG"] = "y"


def arg_destroy():
    ssh = SSHCrossCloud()
    terminate_instance(ssh)
    sys.exit(0)


def arg_provider(arg: str):
    os.environ['PROVIDER'] = arg.upper()


def arg_debug():
    os.environ['DEBUG'] = "y"


def arg_L(arg):
    if os.environ.get('SSH_PARAMS'):
        os.environ["SSH_PARAMS"] = os.environ["SSH_PARAMS"] + " -L " + arg
    else:
        os.environ["SSH_PARAMS"] = " -L " + arg


def arg_R(arg):
    if os.environ.get('SSH_PARAMS'):
        os.environ["SSH_PARAMS"] = os.environ["SSH_PARAMS"] + " -R " + arg
    else:
        os.environ["SSH_PARAMS"] = " -R " + arg


def arg_i(arg):
    os.environ["PEM_SSH"] = "-i " + arg


def arg_no_rsync():
    os.environ['NO_RSYNC_BEGIN'] = "y"
    os.environ['NO_RSYNC_END'] = "y"


def arg_verbose():
    os.environ['RSYNC_VERBOSE'] = "y"


def arg_help():
    help_text = """
    Launch instance, connects to it and leave it alive                          sshcrosscloud.py
    Launch instance, connects to it and stops it (state is saved)	            sshcrosscloud.py --stop
    Launch instance, connects to it and leave it alive           	            sshcrosscloud.py --leave
    Launch instance, launch your command on tmux session         	            sshcrosscloud.py --detach --multiplex "<some command>" 
    Launch instance, connects on a tmux session 	                            sshcrosscloud.py --detach
    Launch instance, connects on a tmux session and attach to it                sshcrosscloud.py --attach
    Synchronize instance directory to local and destroy instance              	sshcrosscloud.py --finish
    Force destruction of the instance    	                                    sshcrosscloud.py --destroy
    """
    logging.info(help_text)
    sys.exit(0)


def arg_status():
    ssh = SSHCrossCloud()
    display_instances(ssh)
    sys.exit(0)


# Other Methods
def display_instances(ssh: SSHCrossCloud):
    if ssh.env['PROVIDER'] == "AZURE":
        nodes = ssh.driver.list_nodes(ssh.env['AZ_RESOURCE_GROUP'])
    else:
        nodes = ssh.driver.list_nodes()

    if not nodes:
        logging.info("No instance running")
        sys.exit(0)

    logging.info("------------------------------------------------------")
    for node in nodes:
        logging.info(node)

    logging.info("------------------------------------------------------")


def set_security_group(ssh: SSHCrossCloud):
    logging.info("Adding your IP address to the security group")

    ssh.driver.ex_create_security_group(ssh.env['SECURITY_GROUP'], ssh.env['SECURITY_GROUP'] + " security group")

    security_groups = ssh.driver.ex_list_security_groups()
    security_group = [sg for sg in security_groups if ssh.env['SECURITY_GROUP'] == sg][0]

    return security_group


def create_instance(ssh: SSHCrossCloud):
    """
    Creates an instance based on the parameters
    :param ssh:
    :return:
    """
    logging.info("Creating instance...")

    if ssh.env['PROVIDER'] == "AWS":
        # Size
        sizes = ssh.driver.list_sizes()
        size = [s for s in sizes if s.id == ssh.env['INSTANCE_TYPE']][0]

        # Image
        images = ssh.driver.list_images()
        image = [i for i in images if ssh.env['IMAGE_ID'] == i.id][0]

        # Security Group
        security_groups = ssh.driver.ex_list_security_groups()
        if ssh.env.get('SECURITY_GROUP'):
            if ssh.env['SECURITY_GROUP'] in security_groups:
                security_group = ssh.env['SECURITY_GROUP']
            elif ssh.env['USERNAME'] in security_groups:
                security_group = ssh.env['USERNAME']
            else:
                security_group = set_security_group(ssh)
        else:
            ssh.env['SECURITY_GROUP'] = ssh.env['USERNAME']
            security_group = set_security_group(ssh)

        # Node Creation
        node = ssh.driver.create_node(name=ssh.env['INSTANCE_NAME'],
                                      image=image,
                                      size=size,
                                      ex_userdata=ssh.env['USER_DATA'],
                                      ex_keyname=ssh.env["USERNAME"],
                                      ex_securitygroup=security_group)

    if ssh.env['PROVIDER'] == "AZURE":
        # Location
        locations = ssh.driver.list_locations()
        location = [i for i in locations if i.id == ssh.env['REGION']][0]

        # Size
        sizes = ssh.driver.list_sizes(location)
        size = [s for s in sizes if ssh.env['INSTANCE_TYPE'] in s.id][0]

        # Image
        images = ssh.driver.list_images(location=location, ex_publisher="Canonical")
        image = [i for i in images if ssh.env['IMAGE_ID'] in i.id][0]

        # Auth
        auth = NodeAuthSSHKey(get_public_key(ssh.env['USERNAME']))

        # Resource Group
        if not ssh.driver.ex_list_resource_groups():
            logging.warning("You must create a Resource Group")
            sys.exit(1)
        else:
            rg = ssh.driver.ex_list_resource_groups()[0]

        # Virtual Network
        if not ssh.driver.ex_list_networks():
            logging.warning("You must create a Virtual Network in Resource Group : " + rg.name)
            sys.exit(1)
        else:
            vn = ssh.driver.ex_list_networks()[0]

        # Security Group
        if not ssh.driver.ex_list_network_security_groups(resource_group=rg.name):
            logging.warning("No Security Group found, it is advised to create one for increased security.")
        else:
            sg = ssh.driver.ex_list_network_security_groups(resource_group=rg.name)[0]

        # Public IP
        if not ssh.driver.ex_list_public_ips(resource_group=rg.name):
            public_ip = ssh.driver.ex_create_public_ip("sshcrosscloud-ip", resource_group=rg.name, location=location,
                                                       public_ip_allocation_method="Dynamic")
        else:
            public_ip = ssh.driver.ex_list_public_ips(resource_group=rg.name)[0]

        # Network Interface
        if not ssh.driver.ex_list_nics(resource_group=rg.name):
            if not ssh.driver.ex_list_subnets(vn):
                logging.warning("You must create a Subnet in Virtual Network : " + vn.name)
                sys.exit(1)
            else:
                sn = ssh.driver.ex_list_subnets(vn)[0]
            ni = ssh.driver.ex_create_network_interface(name="sshcrosscloud-ni", resource_group=rg.name,
                                                        location=location, public_ip=public_ip, subnet=sn)
        else:
            ni = ssh.driver.ex_list_nics(resource_group=rg.name)[0]

        # Node Creation
        node = ssh.driver.create_node(name=ssh.env['INSTANCE_NAME'],
                                      image=image,
                                      size=size,
                                      ex_user_name=ssh.env['INSTANCE_USER'],
                                      auth=auth,
                                      ex_resource_group=rg.name,
                                      ex_network=vn.name,
                                      ex_use_managed_disks=True,
                                      ex_nic=ni,
                                      location=location,
                                      ex_storage_account="useless"  # this argument is useless, but libcloud requires it
                                      )

    if ssh.env['PROVIDER'] == "GCP":
        # Location
        locations = ssh.driver.list_locations()
        location = [l for l in locations if ssh.env['REGION'] in l.name][0]

        # Image
        images = ssh.driver.list_images()
        image = [i for i in images if ssh.env['IMAGE_NAME'] in i.name][0]

        # Size
        sizes = ssh.driver.list_sizes()
        size = [s for s in sizes if ssh.env["INSTANCE_TYPE"] in s.name][0]

        # Metadata (ssh-key)
        metadata = {
            "items": [
                {
                    "key": "ssh-keys",
                    "value": "antoinebourayne:" + get_public_key(ssh.env['USERNAME'])
                }
            ]
        }

        # Node Creation
        node = ssh.driver.create_node(name=ssh.env['INSTANCE_NAME'],
                                      image=image,
                                      size=size,
                                      ex_metadata=metadata)

    # wait_until_running only takes arrays as arguments
    nodes = [node]

    logging.info("Initializating instance...")

    # Azure needs a specified resource group
    if ssh.env['PROVIDER'] == "AZURE":
        list_node_args = {'ex_resource_group': 'NetworkWatcherRG'}
        retour = ssh.driver.wait_until_running(nodes=nodes, ex_list_nodes_kwargs=list_node_args)[0]
    else:
        retour = ssh.driver.wait_until_running(nodes=nodes)[0]

    # retour[0] : (wait_until_running) returns a tuple [(Node, ip_addresses)]
    if not retour[0].public_ips:
        logging.warning("No public IP available")
        return 1

    ssh.env['INSTANCE_ID'] = retour[0].id
    ssh.env['PUBLIC_IP'] = retour[0].public_ips[0]

    return 0


def wait_until_initialization(ssh: SSHCrossCloud):
    """
    Tries to SSH the instance multiple times until it is initialized
    :param ssh:
    :return:0 if OK 1 if error 2 if no instance
    """
    logging.info("Waiting for instance initialization...")
    i = 0

    # Try to connect to instance for a few times
    while i < 10:
        logging.info("Trying to connect... (" + str(i + 1) + ")")
        try:
            # Works like a ping to know if ssh is ok

            if ssh.env.get('DEBUG'):
                ssh_return = "ssh " + ssh.env['DISABLE_HOST_CHECKING'] + " -v " + ssh.env['PEM_SSH'] + " " + ssh.env[
                    'INSTANCE_USER'] + "@" + \
                             ssh.env['PUBLIC_IP'] + " exit && echo $?"
            else:
                ssh_return = "ssh " + ssh.env['DISABLE_HOST_CHECKING'] + " " + ssh.env['PEM_SSH'] + " " + ssh.env[
                    'INSTANCE_USER'] + "@" + \
                             ssh.env['PUBLIC_IP'] + " exit && echo $?"

            output_test = subprocess.check_output(ssh_return, shell=True)
            logging.info("Instance is available")

            return 0

        except subprocess.CalledProcessError as e:
            logging.info("Instance is not yet available")

        time.sleep(5)
        i += 1

    logging.warning("Could not connect to instance, please try later")
    sys.exit(1)


def attach_to_instance(ssh: SSHCrossCloud):
    """
    Open SSH terminal to instance and launch multiplex session if needed
    :param ssh:
    :return: 0 if SSH connection succeeded, 1 if not
    """

    ssh_params = ""
    if ssh.env.get('SSH_PARAMS'):
        ssh_params = ssh.env['SSH_PARAMS']
    if ssh.env.get('DEBUG'):
        ssh_params = ssh_params + " -v"

    ssh_command = "ssh " + ssh.env['DISABLE_HOST_CHECKING'] + ssh_params + " " + ssh.env['PEM_SSH'] + " " \
                  + ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP'] + " "

    if not ssh.env.get('MULTIPLEX'):
        if ssh.env.get('SSH_SCRIPT'):
            logging.info("ssh script : " + ssh_command + ssh.env['SSH_SCRIPT'])
            os.system(ssh_command + ssh.env['SSH_SCRIPT'])
        else:
            logging.info("no ssh script : " + ssh_command)
            os.system(ssh_command)
        return 0
    else:
        if ssh.env.get('SSH_DETACH'):
            if ssh.env.get('SSH_SCRIPT'):
                multiplex_command = ssh_command + " -t 'tmux has-session -t " + ssh.env['INSTANCE_NAME'] \
                                    + " || tmux new-session -s " + ssh.env['INSTANCE_NAME'] + " -d" \
                                    + ' "' + ssh.env['SSH_SCRIPT'] + '"' + "'"
            else:
                multiplex_command = ssh_command + " -t 'tmux has-session -t " + ssh.env['INSTANCE_NAME'] \
                                    + " || tmux new-session -s " + ssh.env['INSTANCE_NAME'] + " -d'"

            logging.info("--detach : " + multiplex_command)
            os.system(multiplex_command)

            return 0

        elif ssh.env.get('SSH_ATTACH'):
            # ssh arg "-t" forces to allocate a terminal, does not not otherwise
            if ssh.env.get('SSH_SCRIPT'):
                multiplex_command = ssh_command + " -t 'tmux attach-session -t " + ssh.env['INSTANCE_NAME'] \
                                    + " || tmux new-session -s " + ssh.env['INSTANCE_NAME'] \
                                    + ' "' + ssh.env['SSH_SCRIPT'] + '"' + "'"
            else:
                multiplex_command = ssh_command + " -t 'tmux attach-session -t " + ssh.env['INSTANCE_NAME'] \
                                    + " || tmux new-session -s " + ssh.env['INSTANCE_NAME'] + "'"

            logging.info("--attach : " + multiplex_command)
            os.system(multiplex_command)

            return 0


def finish_action(ssh: SSHCrossCloud):
    """
    Terminates, destroys or leaves instances depending on the FINAL_STATE
    :param ssh:
    :return:0 if OK 1 if error
    """

    if ssh.env["FINAL_STATE"] == "leave":
        logging.warning("Your instance is still alive")
        sys.exit(0)

    if ssh.env.get("DEBUG") == "y":
        logging.warning("Instance final state : " + ssh.env["FINAL_STATE"])
        sys.exit(0)

    if ssh.nbOfSshConnections < 2:

        if ssh.env["FINAL_STATE"] == "stop":
            logging.warning("Stopping instances...")
            stop_instance(ssh)

        elif ssh.env["FINAL_STATE"] == "terminate":
            logging.warning("Terminating instances...")
            terminate_instance(ssh)

        else:
            if ssh.nbOfSshConnections > 1:
                ssh.env['FINAL_STATE'] = "leave"
                logging.warning("Another connection to EC2 instance is alive. The AWS EC2 instance is active")
            else:
                logging.warning("The AWS EC instance " + ssh.env['INSTANCE_NAME'] + " is alive")


def stop_instance(ssh: SSHCrossCloud):
    """
    Stops all owner's instances
    :param ssh:
    :return:
    """
    if ssh.env['PROVIDER'] == "AZURE":
        nodes = ssh.driver.list_nodes(ssh.env['AZ_RESOURCE_GROUP'])
    else:
        nodes = ssh.driver.list_nodes()

    if not nodes:
        logging.info("No instance running")

    for node in nodes:
        if node.id == ssh.env['INSTANCE_ID'] and node.state != "terminated":
            terminate = ssh.driver.ex_stop_node(node)
            if terminate:
                logging.warning("Stopped : " + node.id)
                return 0
            else:
                logging.warning("An error has occurred while terminating")
                return 1


def terminate_instance(ssh: SSHCrossCloud):
    """
    Terminates all owner's instances
    :param ssh:
    :return:
    """
    if ssh.env['PROVIDER'] == "AZURE":
        nodes = ssh.driver.list_nodes(ssh.env['AZ_RESOURCE_GROUP'])
    else:
        nodes = ssh.driver.list_nodes()

    for node in nodes:
        if node.id == ssh.env['INSTANCE_ID'] and node.state != "terminated":
            if ssh.env['PROVIDER'] == 'AZURE':
                stop = ssh.driver.destroy_node(node=node, ex_destroy_vhd=True, ex_destroy_nic=False)
                volumes = ssh.driver.list_volumes(ex_resource_group=ssh.env['AZ_RESOURCE_GROUP'])
                volume = [v for v in volumes if "sshcrosscloud" in v.name][0]
                delete_volume = ssh.driver.destroy_volume(volume)
            else:
                stop = ssh.driver.destroy_node(node=node)
            if stop:
                logging.warning("Terminated : " + node.id)
                return 0
            else:
                logging.warning("An error has occurred while stopping")
                return 1


def rsync_to_instance(ssh: SSHCrossCloud):
    """
    Using rsync in command line to sync local directory to instance
    :param ssh:
    :return:
    """
    if ssh.env.get('NO_RSYNC_BEGIN'):
        logging.info("No rsync to instance")
    else:
        logging.info("Synchronizing local directory to instance")
        if ssh.env.get('RSYNC_VERBOSE'):
            command = "rsync -Pav -e 'ssh " + ssh.env['DISABLE_HOST_CHECKING'] + " " + ssh.env[
                'PEM_SSH'] + "'" + " --exclude-from='.rsyncignore' $HOME/* " + \
                      ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP'] + ":/home/" + ssh.env['INSTANCE_USER']
        else:
            command = "rsync -Pa -e 'ssh " + ssh.env['DISABLE_HOST_CHECKING'] + " " + ssh.env[
                'PEM_SSH'] + "'" + " --exclude-from='.rsyncignore' $HOME/* " + \
                      ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP'] + ":/home/" + ssh.env['INSTANCE_USER']

        rsync = os.system(command)


def rsync_back_to_local(ssh: SSHCrossCloud):
    """
    Rsync back
    :param ssh:
    :return:
    """
    if ssh.env.get('NO_RSYNC_END'):
        logging.info("No rsync back to local")
    else:
        logging.info("Synchronizing directory back to local")
        if ssh.env.get('RSYNC_VERBOSE'):
            command = "rsync -vzaP -r -e 'ssh -o StrictHostKeyChecking=no -o LogLevel=quiet " + ssh.env[
                'PEM_SSH'] + "' " \
                      + ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP'] + \
                      ":/home/" + ssh.env['INSTANCE_USER'] + "/*" + " $HOME"
        else:
            command = "rsync -zaP -r -e 'ssh -o StrictHostKeyChecking=no -o LogLevel=quiet " + ssh.env[
                'PEM_SSH'] + "' " \
                      + ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP'] + \
                      ":/home/" + ssh.env['INSTANCE_USER'] + "/*" + " $HOME"

        rsync = os.system(command)


if __name__ == '__main__':
    main()
