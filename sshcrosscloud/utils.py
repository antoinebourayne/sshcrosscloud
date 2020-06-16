import logging
import os
import sys
from pathlib import Path
import coloredlogs

"""
Here are implemented strings and functions used in more than one file

"""

guide_aws = """
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

guide_azure = """
To configure Azure credentials, you must follow the instructions below:
(Note that you can configure everything on https://portal.azure.com/
1. Create an Application
az ad app create --display-name "<Your Application Display Name>" --password <Your_Password
2. Create a Service principa
az ad sp create --id "<Application_Id>
3 . Assign role
az role assignment create --assignee "<Object_Id>" --role Owner --scope /subscriptions/{subscriptionId}
4. Create a file in /HOME/.azure/credentials.txt and store the credentials you created as follows
[default]
subscription_id=XXXXXXXXXXXXXXXXXXX
client_id=XXXXXXXXXXXXXXXXXXX
secret=XXXXXXXXXXXXXXXXXXX
tenant=XXXXXXXXXXXXXXXXXX
3. Create a Resource Group
az group create -l <myRegion> -n <MyResourceGroup>
(run 'az account list-locations' if you don't know the regions names
4. Create a Virtual Networ
az network vnet create --name <myVirtualNetwork> --resource-group <myResourceGroup> --subnet-name <default>  
"""

guide_gcp = """
"""

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

default_args = {'sshscript': None,
                'leave': False,
                'stop': False,
                'terminate': False,
                'finish': False,
                'detach': False,
                'attach': False,
                'verbose': False,
                'status': False,
                'destroy': False,
                'norsync': False,
                'debug': False,
                'v': False,
                'provider': None,
                'L': None,
                'R': None,
                'i': None}


class AWS:
    pass


class Azure:
    pass


class GCP:
    pass


class SSHVar:
    def __init__(self, arg_dict: dict):
        self.arg_dict = arg_dict

        # Parser Commands
        self.provider = arg_dict.get('provider')
        self.ssh_script = arg_dict.get('sshscript')
        self.leave = arg_dict.get('leave')
        self.stop = arg_dict.get('stop')
        self.terminate = arg_dict.get('terminate')
        self.detach = arg_dict.get('detach')
        self.attach = arg_dict.get('attach')
        self.finish = arg_dict.get('finish')
        self.verbose = arg_dict.get('verbose')
        self.norsync = arg_dict.get('norsync')
        self.l = arg_dict.get('l')
        self.r = arg_dict.get('r')
        self.i = arg_dict.get('i')
        self.v = arg_dict.get('v')
        self.debug = arg_dict.get('debug')
        self.config = arg_dict.get('config')
        self.status = arg_dict.get('status')
        self.destroy = arg_dict.get('destroy')

        # Fonctional Variables
        self.polygram = None
        self.username = None
        self.ssh_params = ""
        self.pem_ssh = None
        self.display_nodes = True
        self.provider_dict = None
        self.ssh_detach = False
        self.ssh_attach = False
        self.multiplex = False
        self.no_rsync_begin = False
        self.no_rsync_end = False
        self.no_attach = False
        self.no_wait_until_init = False
        self.rsync_verbose = False
        self.debug = False
        self.instance_name = None
        self.sshcrosscloud_instance_id = None
        self.instance_state = None
        self.public_ip = None
        self.user_data = None
        self.instance_user = None
        self.credentials_file_path = None
        self.instance_spec_arg = None
        self.rsa_key_file_path = None
        self.rsa_key_name = None
        self.status_mode = False
        self.rsync_directory = os.path.expanduser('~')
        self.credentials_items = []
        self.final_state = "terminate"
        self.ssh_default_params = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=quiet"
        self.nbOfSshConnections = 0

        # AWS Object
        self.aws = AWS
        self.aws.access_key_id = None
        self.aws.secret_access_key = None
        self.aws.default_user_list = {
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
        self.aws.region = 'eu-central-1'
        self.aws.size = 't2.micro'
        self.aws.security_group = 'sshcrosscloud'
        self.aws.image_id = 'ami-0e342d72b12109f91'
        self.aws.image_name = 'ubuntu'
        self.aws.credentials_path = os.path.expanduser('~') + "/.aws/credentials"
        self.aws.config_path = os.path.expanduser('~') + "/.aws/config"
        self.aws.credentials_items = ['aws_access_key_id', 'aws_secret_access_key']

        # Azure Variables
        self.azure = Azure
        self.azure.tenant_id = None
        self.azure.subscription_id = None
        self.azure.application_id = None
        self.azure.secret = None
        self.azure.public_ip_name = None
        self.azure.virtual_network = None
        self.azure.subnet = 'default'
        self.azure.region = 'westus'
        self.azure.size = 'Standard_B1ls'
        self.azure.network_interface = 'sshcrosscloud-ni'
        self.azure.image_id = 'UbuntuServer:16.04'
        self.azure.image_name = 'ubuntu'
        self.azure.resource_group = 'NetworkWatcherRG'
        self.azure.publisher = 'Canonical'
        self.azure.credentials_path = os.path.expanduser('~') + "/.azure/credentials"
        self.azure.credentials_items = ['tenant', 'subscription_id', 'client_id', 'secret']

        # GCP Variables
        self.gcp = GCP
        self.gcp.user_id = None
        self.gcp.key_path = None
        self.gcp.project = None
        self.gcp.data_center = None
        self.gcp.region = 'us-central1-a'
        self.gcp.size = 'f1-micro'
        self.gcp.image_name = 'ubuntu'
        self.gcp.credentials_path = os.path.expanduser('~') + "/.gcp/credentials"
        self.gcp.credentials_items = ['user_id', 'key', 'project', 'datacenter']


def get_string_from_file(filepath):
    with open(filepath, 'r') as userdatafile:
        return userdatafile.read()


def get_public_key(private_key_path: str) -> str:
    if os.path.isfile(private_key_path + ".pub"):
        with open(private_key_path + ".pub", 'r') as file:
            rsa_pub = file.read()
        return rsa_pub
    else:
        raise Exception(private_key_path + ".pub not found, add --config to create one")


def get_ui_credentials(path: str, credentials_items: list):
    if os.path.isfile(path):
        with open(path, 'r+') as file:
            file_data = file.read()
            if file_data:
                answer = get_ui_confirmation("Credentials have already been saved, would you like to change them?")
                if answer:
                    list_of_credentials = {}
                    for i in credentials_items:
                        print("Enter " + i + ":")
                        input_credential = input()
                        list_of_credentials[i] = input_credential
                    return list_of_credentials
                else:
                    logging.info("Credentials have not been changed")
                    return

    return


def get_ui_confirmation(message: str):
    print(message + " y/n")
    while 1:
        answer = input()
        if answer == 'y':
            return True
        if answer == 'n':
            return False
        else:
            print("Must provide 'y' or 'n' answer")
