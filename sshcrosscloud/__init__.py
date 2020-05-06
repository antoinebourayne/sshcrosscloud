import getpass
import getpass as gt
import platform
import subprocess
import time
import logging
import click
from pathlib import Path
from os import environ
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from libcloud.compute.base import NodeAuthSSHKey
from dotenv import find_dotenv, dotenv_values
import os
import socket
import sys

"""

SSH-EC2 Python Version

"""

aws_default_dict = {
    'FINAL_STATE': 'leave',
    'REGION': "eu-central-1",
    'INSTANCE_TYPE': "t2.micro",
    'USER_DATA': "",
    'SECURITY_GROUP': "homeANBO",
    'IMAGE_ID': "ami-0e342d72b12109f91",
    'IMAGE_NAME': "ubuntu"
}

azure_default_dict = {
    'FINAL_STATE': 'leave',
    'REGION': "us-central1-a",
    'INSTANCE_TYPE': "f1-micro",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
    'IMAGE_ID': "UbuntuServer:16.04",
}

gcp_default_dict = {
    'FINAL_STATE': 'leave',
    'REGION': "us-central1-a",
    'INSTANCE_TYPE': "f1-micro",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
}


# TODO: remplir les "help"
@click.command()
# FLAGS
@click.option('--leave/--no-leave', default=False, help="")
@click.option('--stop/--no-stop', default=False, help="")
@click.option('--terminate/--no-terminate', default=False, help="")
@click.option('--detach/--no-detach', default=False, help="")
@click.option('--attach/--no-attach', default=False, help="")
@click.option('--finish/--no-finish', default=False, help="")
@click.option('--verbose/--no-verbose', default=False, help="")
@click.option('--help/--no-help', default=False, help="")
@click.option('--status/--no-status', default=False, help="")
@click.option('--destroy/--no-destroy', default=False, help="")
@click.option('--rsync/--no-rsync', default=True, help="")
@click.option('--debug/--no-debug', default=False, help="")
@click.option('--config/--no-config', default=False, help="")
# VALUES
@click.option('--multiplex', help="")
@click.option('--provider', help="")
@click.option('--l', default="", help="")
@click.option('--r', default="", help="")
@click.option('--i', default="", help="")
# MAIN
def main(leave, stop, terminate, detach, attach, finish, verbose, help, status, destroy, rsync, debug, config,
         multiplex,
         provider, l, r, i):
    # Logs settings
    logging.getLogger().setLevel(logging.INFO)

    # Arguments
    if leave:
        arg_leave()

    if stop:
        arg_stop()

    if terminate:
        arg_terminate()

    if detach:
        arg_detach()

    if attach:
        arg_attach()

    if finish:
        arg_finish()

    if verbose:
        arg_verbose()

    if help:
        arg_help()

    if not rsync:
        arg_no_rsync()

    if multiplex is not None:
        arg_multiplex(multiplex)

    if provider is not None:
        arg_provider(provider)
    else:
        logging.warning("You must specify a provider")
        sys.exit(1)

    if l is not None:
        arg_L(l)

    if r is not None:
        arg_R(r)

    if i is not None:
        arg_i(i)

    if debug:
        arg_debug()

    if config:
        arg_config()

    if status:
        arg_status()

    if destroy:
        arg_destroy()

    """-----------------Here call methods---------------------"""
    logging.info('-----SSH CROSS CLOUD-----')

    # SSH Object
    ssh = SSHCrossCloud()

    display_aws_instance_characteristics(ssh)

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


# SshDataScience object contains and initializes the variables
class SSHCrossCloud:
    nbOfSshConnections = 0

    def __init__(self):
        # By default is default
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
            self.default_dict = aws_default_dict
        elif os.environ['PROVIDER'] == 'AZURE':
            self.default_dict = azure_default_dict
        elif os.environ['PROVIDER'] == 'GCP':
            self.default_dict = gcp_default_dict
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


def get_public_key() -> str:
    with open(Path.home() / ".ssh/ANBO.pub", 'r') as file:
        rsa_pub = file.read()
    return rsa_pub


def get_string_from_file(filepath):
    with open(filepath, 'r') as userdatafile:
        return userdatafile.read()


def get_region():
    with open(Path.home() / ".aws/config", 'r') as file:
        data = file.read().replace('\n', '')
        REGION = data.split("region = ", 1)[1]
        return REGION


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
        abort()


def get_aws_credentials(ssh: SSHCrossCloud):
    if os.path.isfile(str(Path.home()) + "/.aws/credentials"):
        with open(str(Path.home()) + "/.aws/credentials", 'r') as file:
            data = file.read()

            start = 'aws_access_key_id = '
            end = '\n'
            aws_access_key_id = (data.split(start))[1].split(end)[0]

            start = 'aws_secret_access_key =  '
            end = '\n'
            aws_secret_access_key = (data.split(start))[1].split(end)[0]

            return aws_access_key_id, aws_secret_access_key
    else:
        logging.warning("No credentials found in " + str(Path.home()) + "/.aws/credentials")
        logging.info(
            "Please run 'sshcrosscloud --config --provider " + ssh.env['PROVIDER'] + "' to configure credentials")
        abort()


def get_azure_credentials(ssh: SSHCrossCloud):
    if os.path.isfile(str(Path.home()) + "/.azure/credentials.txt"):
        with open(str(Path.home()) + "/.azure/credentials.txt", 'r') as file:
            data = file.read()

            start = 'tenant='
            end = '\n'
            tenant_id = (data.split(start))[1].split(end)[0]

            start = 'subscription_id='
            end = '\n'
            subscription_id = (data.split(start))[1].split(end)[0]

            start = 'client_id='
            end = '\n'
            client_id = (data.split(start))[1].split(end)[0]

            start = 'secret='
            end = '\n'
            secret = (data.split(start))[1].split(end)[0]

            return tenant_id, subscription_id, client_id, secret
    else:
        logging.warning("No credentials found in " + str(Path.home()) + "/.azure/credentials.txt")
        logging.info(
            "Please run 'sshcrosscloud --config --provider " + ssh.env['PROVIDER'] + "' to configure credentials")
        abort()


def get_azure_resource_group(ssh: SSHCrossCloud):
    if not ssh.driver.ex_list_resource_groups():
        logging.warning("No Resource Group found, you must create one")
        logging.info("You can run 'az group create -l <REGION> -n <NAME>' or create one on https://portal.azure.com/")
        abort()
    else:
        rg = ssh.driver.ex_list_resource_groups()[0]
        return rg


def get_gcp_credentials(ssh: SSHCrossCloud):
    if os.path.isfile(str(Path.home()) + "/.gcp/credentials.txt"):
        with open(str(Path.home()) + "/.gcp/credentials.txt", 'r') as file:
            data = file.read()

            start = 'user_id='
            end = '\n'
            user_id = (data.split(start))[1].split(end)[0]

            start = 'key='
            end = '\n'
            key = (data.split(start))[1].split(end)[0]

            start = 'project='
            end = '\n'
            project = (data.split(start))[1].split(end)[0]

            start = 'datacenter='
            end = '\n'
            datacenter = (data.split(start))[1].split(end)[0]

            return user_id, key, project, datacenter
    else:
        logging.warning("No credentials found in " + str(Path.home()) + "/.gcp/credentials.txt")
        logging.info(
            "Please run 'sshcrosscloud --config --provider " + ssh.env['PROVIDER'] + "' to configure credentials")
        abort()


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
    if not ssh.env.get("POLYGRAM"):
        ssh.env["POLYGRAM"] = get_login()
    if not ssh.env.get('AWS_KEY_NAME'):
        ssh.env['AWS_KEY_NAME'] = ssh.env['POLYGRAM']
    if not ssh.env.get('INSTANCE_NAME'):
        ssh.env['INSTANCE_NAME'] = ssh.env['AWS_KEY_NAME'].lower() + "-" + ssh.env['PROJECT_NAME']
    if not ssh.env.get('AWS_RSYNC_DIR'):
        ssh.env['AWS_RSYNC_DIR'] = os.getcwd()
    if not ssh.env.get("REGION"):
        ssh.env["REGION"] = get_region()

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
        'POLYGRAM': ssh.env['POLYGRAM']
    }

    ssh.env['AWS_TAGS'] = "[" + str(tags) + "]"

    return ssh.env


# TODO : changer nom POLYGRAM

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


def auto_config(provider: str):
    if provider == 'AWS':
        aws_login = "aws configure"
        # Credentials
        try:
            os.system(aws_login)
        except:
            try:
                install_aws_cli = "pip3 install awscli --upgrade --user"
                os.system(install_aws_cli)
                os.system(aws_login)
            except:
                logging.warning("Error, cannot get the AWS CLI")

        # Polygram
        logging.info("Enter your Polygram (this will be your signature while managing VMs) :")
        polygram = input()

        if platform.system() == 'Linux':
            rc = str(Path.home()) + "/.bashrc"
        elif platform.system() == 'Darwin':
            rc = str(Path.home()) + "/.bash_profile"
        else:
            logging.warning("OS not supported")
            sys.exit(1)
        if os.path.isfile("/home/antoinebourayne/.zshrc"):
            rc = str(Path.home()) + "/.zshrc"

        with open('/home/antoinebourayne/.bashrc', 'a') as file:
            bash_line = "export POLYGRAM=" + polygram
            file.write('\n' + bash_line + '\n')

        os.system(". " + rc)

        # SSH Key-Pair
        create_key_pair_command = "(cd " + str(Path.home()) + "/.ssh &&" \
                                  " aws ec2 create-key-pair --key-name " + os.environ['POLYGRAM'] + \
                                  " --output text > " + os.environ['POLYGRAM'] + ".pem &&" \
                                  " chmod 400 " + os.environ['POLYGRAM'] + ".pem)"
        os.system(create_key_pair_command)
        logging.info("Configuration done, you can now run 'python sshcrosscloud/__init__.py --provider aws'")


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
    if os.environ["SSH_DETACH"] != "y" and os.environ["SSH_ATTACH"] != "y":
        os.environ["FINAL_STATE"] = "stop"


def arg_terminate():
    if os.environ["SSH_DETACH"] != "y" and os.environ["SSH_ATTACH"] != "y":
        os.environ["FINAL_STATE"] = "terminate"


def arg_detach():
    os.environ["FINAL_STATE"] = "leave"
    os.environ["SSH_DETACH"] = "y"
    os.environ["MULTIPLEX"] = "y"
    os.environ["NO_RSYNC_END"] = "y"


def arg_attach():
    os.environ["MULTIPLEX"] = "y"
    os.environ["SSH_ATTACH"] = "y"
    os.environ["FINAL_STATE"] = "leave"
    os.environ["NO_RSYNC_BEGIN"] = "y"
    os.environ["NO_RSYNC_END"] = "y"


def arg_finish():
    os.environ["NO_RSYNC_BEGIN"] = "y"
    os.environ["NO_ATTACH"] = "y"


def arg_config():
    # guide_credentials(os.environ["PROVIDER"])
    if os.environ['PROVIDER'] == 'AWS':
        auto_config(os.environ['PROVIDER'])
    sys.exit(0)


def arg_destroy():
    ssh = SSHCrossCloud()
    terminate_instance(ssh)
    sys.exit(0)


def arg_multiplex(arg):
    os.environ["MULTIPLEX"] = arg
    if os.environ["MULTIPLEX"] is None:
        os.environ["MULTIPLEX"] = ""


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
    os.environ['RSYNC_QUIET'] = ""


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

        # Node Creation
        node = ssh.driver.create_node(name=ssh.env['INSTANCE_NAME'],
                                      image=image,
                                      size=size,
                                      ex_userdata=ssh.env['USER_DATA'],
                                      ex_keyname=ssh.env["POLYGRAM"],
                                      ex_securitygroup=ssh.env["SECURITY_GROUP"])

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
        auth = NodeAuthSSHKey(get_public_key())

        # Resource Group
        if not ssh.driver.ex_list_resource_groups():
            logging.warning("You must create a Resource Group")
            abort()
        else:
            rg = ssh.driver.ex_list_resource_groups()[0]

        # Virtual Network
        if not ssh.driver.ex_list_networks():
            logging.warning("You must create a Virtual Network in Resource Group : " + rg.name)
            abort()
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
                abort()
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
                    "value": "antoinebourayne:" + get_public_key()
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
        # TODO : ne marche pas pour GCP
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
            if ssh.env.get('DEBUG'):
                # Works like a ping to know if ssh is ok
                ssh_return = "ssh -v -i $HOME/.ssh/" + ssh.env['POLYGRAM'] + " " + ssh.env['INSTANCE_USER'] + "@" + \
                             ssh.env['PUBLIC_IP'] + " exit && echo $?"
            else:
                # Works like a ping to know if ssh is ok
                ssh_return = "ssh -i $HOME/.ssh/" + ssh.env['POLYGRAM'] + " " + ssh.env['INSTANCE_USER'] + "@" + \
                             ssh.env['PUBLIC_IP'] + " exit && echo $?"
            output_test = subprocess.check_output(ssh_return, shell=True)

            if "0" in str(output_test):
                logging.info("Instance is available")

            return 0
        except:
            pass

        time.sleep(5)
        i += 1

    # SSH connection couldn't be established
    return 1


def attach_to_instance(ssh: SSHCrossCloud):
    """
    Open SSH terminal to instance and launch multiplex session if needed
    :param ssh:
    :return: 0 if SSH connection succeeded, 1 if not
    """
    if ssh.env.get('NO_ATTACH'):
        logging.info("Skipping attach to instance")
        return 0
    if ssh.env.get('DEBUG'):
        ssh_command = "ssh -v -i $HOME/.ssh/" + ssh.env['POLYGRAM'] + " " \
                      + ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP']
    else:
        ssh_command = "ssh -i $HOME/.ssh/" + ssh.env['POLYGRAM'] + " " \
                      + ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP']

    if not ssh.env.get('MULTIPLEX'):
        os.system(ssh_command)
        return 0
    else:
        if ssh.env.get('SSH_DETACH'):
            multiplex_command = ssh_command + " 'tmux new-session -s sshcrosscloud -d" \
                                + ' "' + ssh.env['MULTIPLEX'] + '"' + "'"
            os.system(multiplex_command)

        elif ssh.env.get('SSH_ATTACH'):
            multiplex_command = ssh_command + " -t 'tmux new-session -s sshcrosscloud" \
                                + ' "' + ssh.env['MULTIPLEX'] + '"' + "'"
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
        abort()

    if ssh.nbOfSshConnections < 2:

        if ssh.env["FINAL_STATE"] == "stop":
            logging.warning("Stopping instances...")
            stop_instance(ssh)
            # TODO : dry run (voir dans ssh-ec2)

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
        logging.info("No rsync back to local")
    else:
        logging.info("Synchronizing local directory to instance")
        if ssh.env.get('DEBUG'):
            command = "rsync -v -Pav -e 'ssh -i " + ssh.env['HOME'] + "/.ssh/" + ssh.env[
                'POLYGRAM'] + "'" + " --exclude-from='.rsyncignore' $HOME " + \
                      ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP'] + ":/home/" + ssh.env['INSTANCE_USER']
        else:
            command = "rsync -Pav -e 'ssh -i " + ssh.env['HOME'] + "/.ssh/" + ssh.env[
                'POLYGRAM'] + "'" + " --exclude-from='.rsyncignore' $HOME " + \
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
        if ssh.env.get('DEBUG'):
            command = "rsync -v -chavzP --stats " + ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP'] + \
                      ":/home/" + ssh.env['INSTANCE_USER'] + "/" + ssh.env['USER'] + "/*" + " $HOME"
        else:
            command = "rsync -chavzP --stats " + ssh.env['INSTANCE_USER'] + "@" + ssh.env['PUBLIC_IP'] + \
                      ":/home/" + ssh.env['INSTANCE_USER'] + "/" + ssh.env['USER'] + "/*" + " $HOME"

        rsync = os.system(command)


def abort():
    logging.warning("Aborted")
    sys.exit(1)


if __name__ == '__main__':
    main()
