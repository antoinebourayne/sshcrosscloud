import logging
import os
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


class AWS:
    pass


class Azure:
    pass


class GCP:
    pass


class SSHVar:
    def __init__(self, arg_dict: dict):

        self.arg_dict = arg_dict

        # Fonctional Variables
        self.ssh_script = None
        self.polygram = None
        self.username = None
        self.provider = None
        self.ssh_params = None
        self.pem_ssh = None
        self.provider_dict = None
        self.ssh_detach = False
        self.ssh_attach = False
        self.multiplex = False
        self.no_rsync_begin = False
        self.no_rsync_end = False
        self.no_attach = False
        self.no_wait_until_init = False
        self.config = False
        self.rsync_verbose = False
        self.debug = False
        self.instance_name = None
        self.instance_id = None
        self.instance_state = None
        self.public_ip = None
        self.user_data = None
        self.instance_user = None
        self.credentials_file_path = None
        self.instance_spec_arg = None
        self.status_mode = False
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
        self.aws.credentials_path = str(Path.home()) + "/.aws/credentials"
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
        self.azure.credentials_path = str(Path.home()) + "/.azure/credentials"
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
        self.gcp.credentials_path = str(Path.home()) + "/.gcp/credentials"
        self.gcp.credentials_items = ['user_id', 'key', 'project', 'datacenter']

        self._init_commands()

    def _init_commands(self):
        # TODO: here implement check_params from sshcrosscloud class
        # SSH Script
        if self.arg_dict.get('sshscript'):
            self.ssh_script = self.arg_dict.get('sshscript')

        # Arguments
        if self.arg_dict['leave']:
            self.final_state = "leave"

        if self.arg_dict['stop']:
            self.final_state = "stop"

        if self.arg_dict['terminate']:
            self.final_state = "terminate"

        if self.arg_dict['detach']:
            self.final_state = "leave"
            self.ssh_detach = True
            self.multiplex = True

        if self.arg_dict['attach']:
            self.final_state = "leave"
            self.ssh_attach = True
            self.multiplex = True
            self.no_rsync_begin = True
            self.no_rsync_end = True

        if self.arg_dict['finish']:
            self.no_rsync_begin = True

        if self.arg_dict['verbose']:
            self.rsync_verbose = True

        if self.arg_dict['norsync']:
            self.no_rsync_begin = True
            self.no_rsync_end = True

        if self.arg_dict['provider']:
            self.provider = self.arg_dict['provider']

        if self.arg_dict['L']:
            self.ssh_params = self.ssh_params + " -L " + self.arg_dict['L']

        if self.arg_dict['R']:
            self.ssh_params = self.ssh_params + " -R " + self.arg_dict['L']

        if self.arg_dict['i']:
            self.pem_ssh = "-i" + self.arg_dict['i']

        if self.arg_dict['v']:
            logging.getLogger().setLevel(logging.INFO)
            coloredlogs.install(level='INFO')

        if self.arg_dict['debug']:
            self.debug = True

        if self.arg_dict['config']:
            self.config = True

        if self.arg_dict['status']:
            self.status_mode = True
            self.no_rsync_begin = True
            self.no_rsync_end = True
            self.no_attach = True
            self.no_wait_until_init = True

        if self.arg_dict['destroy']:
            self.no_rsync_begin = True
            self.no_rsync_end = True
            self.no_attach = True
            self.final_state = "terminate"


def get_string_from_file(filepath):
    with open(filepath, 'r') as userdatafile:
        return userdatafile.read()


def get_public_key(name: str) -> str:
    if os.path.isfile(str(Path.home()) + "/.ssh/" + name + ".pub"):
        with open(str(Path.home()) + "/.ssh/" + name + ".pub", 'r') as file:
            rsa_pub = file.read()
        return rsa_pub
    else:
        raise Exception(str(Path.home()) + "/.ssh/" + name + ".pub " + "not found, add --config to create one")


def get_ui_credentials(ssh):
    if ssh.ssh_vars.config:
        default_credentials_path = str(Path.home()) + "/." + ssh.ssh_vars.provider + "/credentials"
        if os.path.isfile(default_credentials_path):
            with open(default_credentials_path, 'r+') as file:
                file_data = file.read()
                if file_data:
                    logging.info("Credentials have already been saved, would you like to change them? y/n")
                    answer = input()
                    if answer == 'y':
                        list_of_credentials = {}
                        for i in ssh.ssh_vars.credentials_items:
                            print("Enter" + i + ":")
                            input_credential = input()
                            list_of_credentials[i] = input_credential

                        return list_of_credentials
                    else:
                        logging.info("Credentials have not been changed")
                        return

    return
