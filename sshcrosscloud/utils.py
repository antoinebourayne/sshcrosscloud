import os
from pathlib import Path

# TODO: stocker les chaines de caractères os.command ici ?

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

global_dict = {
    'DISABLE_HOST_CHECKING': "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=quiet",
    'FINAL_STATE': 'terminate'
}

aws_default_dict = {
    'REGION': "eu-central-1",
    'INSTANCE_TYPE': "t2.micro",
    'USER_DATA': "",
    'SECURITY_GROUP': "sshcrosscloud",
    'IMAGE_ID': "ami-0e342d72b12109f91",
    'IMAGE_NAME': "ubuntu",
    # TODO: update this value everywhere in the code where needed
    'PROVIDER_FILE_PATH': str(Path.home()) + "/.aws/credentials",
}

azure_default_dict = {
    'REGION': "westus",
    'INSTANCE_TYPE': "Standard_B1ls",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
    'IMAGE_ID': "UbuntuServer:16.04",
    'AZ_RESOURCE_GROUP': "NetworkWatcherRG",
    'AZ_PUBLISHER': "Canonical",
    'PROVIDER_FILE_PATH': str(Path.home()) + "/.azure/credentials"
}

gcp_default_dict = {
    'REGION': "us-central1-a",
    'INSTANCE_TYPE': "f1-micro",
    'IMAGE_NAME': "ubuntu",
    'USER_DATA': "",
    'PROVIDER_FILE_PATH': str(Path.home()) + "/.gcp/credentials"
}

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
