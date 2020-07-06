import inspect
import logging
import os
import sys

from dotenv import dotenv_values, find_dotenv

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
                'config': False,
                'v': True,
                'provider': 'aws',
                'L': None,
                'R': None,
                'i': None}

aws_default_user_list = {
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


class AWS:
    pass


class Azure:
    pass


class GCP:
    pass


class SSHParams:
    def __init__(self, **params):

        # Parser Commands
        self.provider = params.get('provider')
        self.ssh_script = params.get('sshscript')
        self.leave = params.get('leave')
        self.stop = params.get('stop')
        self.terminate = params.get('terminate')
        self.detach = params.get('detach')
        self.attach = params.get('attach')
        self.finish = params.get('finish')
        self.norsync = params.get('norsync')
        self.l = params.get('l')
        self.r = params.get('r')
        self.i = params.get('i')
        self.verbose = params.get('v')
        self.config = params.get('config')
        self.status = params.get('status')
        self.destroy = params.get('destroy')

        # Fonctional Variables
        self.polygram = None
        self.username = None
        self.ssh_params = ""
        self.pem_ssh = None
        self.display_nodes = False
        self.provider_dict = None
        self.ssh_detach = False
        self.ssh_attach = False
        self.multiplex = False
        self.no_rsync_begin = False
        self.no_rsync_end = False
        self.no_attach = False
        self.no_wait_until_init = False
        self.instance_name = None
        self.sshcrosscloud_instance_id = None
        self.instance_state = None
        self.public_ip = None
        self.user_data = None
        self.instance_user = None
        self.credentials_file_path = None
        self.instance_spec_arg = None
        self.rsa_private_key_file_path = None
        self.rsa_key_name = None
        self.status_mode = False
        self.credentials_name = None
        self.general_name = "sshcrosscloud"
        self.rsync_directory = os.path.expanduser('~')
        self.user_data_file_path = ".user_data"
        self.credentials_items = []
        self.final_state = "terminate"
        self.ssh_fonctionnal_params = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=quiet"
        self.nbOfSshConnections = 0
        self.provider_list = ['aws', 'azure', 'gcp']

        # AWS Object
        self.aws = AWS()
        self.aws.access_key_id = None
        self.aws.secret_access_key = None
        self.aws.region = 'eu-central-1'
        self.aws.size = 't2.micro'
        self.aws.security_group = 'sshcrosscloud'
        self.aws.image_id = 'ami-0e342d72b12109f91'
        self.aws.image_name = 'ubuntu'
        self.aws.credentials_path = os.path.expanduser('~') + "/.aws/credentials"
        self.aws.config_path = os.path.expanduser('~') + "/.aws/config"
        self.aws.credentials_items = ['aws_access_key_id', 'aws_secret_access_key']
        self.aws.credentials_name = 'default'

        # Azure Variables
        self.azure = Azure()
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
        self.azure.credentials_name = 'default'

        # GCP Variables
        self.gcp = GCP()
        self.gcp.user_id = None
        self.gcp.key_path = None
        self.gcp.project = None
        self.gcp.data_center = None
        self.gcp.region = 'us-central1-a'
        self.gcp.size = 'f1-micro'
        self.gcp.image_name = 'ubuntu'
        self.gcp.credentials_path = os.path.expanduser('~') + "/.gcp/credentials"
        self.gcp.credentials_items = ['user_id', 'key', 'project', 'datacenter']
        self.gcp.credentials_name = 'default'

    def update_custom_values(self, replace_dotenv: bool, replace_environ: bool):
        """
        This method creates a dict with dotenv values updated by the environment values,
        then store them in the ssh_var object

        :param replace_dotenv: Flag to get dotenv values
        :type replace_dotenv: ``bool``

        :return: Flag to get environnment values
        :rtype: ``bool``
        """
        # Default
        env = {}

        if replace_dotenv:
            dotenv = dotenv_values(find_dotenv())
            for k, v in dotenv.items():
                env[k] = v

        if replace_environ:
            environ = os.environ
            for k, v in environ.items():
                env[k] = v

        for attr, value in self.__dict__.items():
            if env.get(attr.upper()):
                setattr(self, attr, env.get(attr.upper()))

        for name, obj in inspect.getmembers(self):
            if name in self.provider_list:
                for attr, value in obj.__dict__.items():
                    if env.get(str(attr.upper())):
                        setattr(obj, attr, env.get(attr.upper()))


def get_string_from_file(filepath):
    """
    Return the raw string from a string file path

    :param filepath: Key Path
    :type filepath: ``str``

    :return: File raw content
    :rtype: ``str``
    """
    try:
        if os.path.isfile(filepath):
            with open(filepath, 'r') as userdatafile:
                return userdatafile.read()
    except Exception as e:
        print(e)
        return None


def get_public_key(private_key_path: str) -> str:
    """
    Return the RSA public key from a string key path

    :param private_key_path: Private key path
    :type private_key_path: ``str``

    :return: RSA public key
    :rtype: :``str``
    """
    if os.path.isfile(private_key_path + ".pub"):
        with open(private_key_path + ".pub", 'r') as file:
            rsa_pub = file.read()
        return rsa_pub
    else:
        raise Exception(private_key_path + ".pub not found, add --config to create one")


def get_ui_confirmation(message: str):
    """
    Get user confirmation to a message

    :param message: Message displayed to the user
    :type message: ``str``

    :return: User answer: (True: yes False: no)
    :rtype: :``bool``
    """
    print(message + " y/n")
    while 1:
        answer = input()
        if answer == 'y':
            return True
        if answer == 'n':
            return False
        else:
            print("Must provide 'y' or 'n' answer")