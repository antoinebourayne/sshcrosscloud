import configparser
import logging
import os
import stat
from pathlib import Path

# TODO: stocker les chaines de caractères os.command ici


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


# Cannot be an SSHCrossCloud Method because called before creation of object
def set_credentials(provider: str):
    # TODO: do the other provider
    if provider == 'AWS':
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
            with open(str(Path.home()) + "/.aws/credentials", 'w') as cred_file:

                logging.info("Enter AWS ACCESS KEY ID:")
                aws_access_key_id = input()
                logging.info("Enter AWS SECRET ACCESS ID:")
                aws_secret_access_key = input()

                config = configparser.ConfigParser()
                config['DEFAULT'] = {'aws_access_key_id': aws_access_key_id,
                                     'aws_secret_access_key': aws_secret_access_key}

                config.write(cred_file)
                logging.info("Credentials have been saved")
                return 0
        else:
            logging.warning("AWS Credentials file does not exist")
            return 1
    else:
        logging.warning("Set credentials not yet implemented for this provider")


def create_local_rsa_key_pair(name: str):
    # TODO: make it testable
    logging.info("Creating key pair")

    genrate_key_pair = "ssh-keygen -f " + str(Path.home()) + "/.ssh/" + name

    pub_from_priv = "ssh-keygen -y -f " + str(Path.home()) + "/.ssh/" \
                    + name + " > " + str(Path.home()) \
                    + "/.ssh/" + name + ".pub"

    if os.path.isfile(str(Path.home()) + "/.ssh" + name):
        logging.info("Creating key pair from existing key in " + str(Path.home()) + "/.ssh" + name)
        os.system(pub_from_priv)
    else:
        os.system(genrate_key_pair)
        os.chmod(str(Path.home()) + "/.ssh/" + name, stat.S_IRWXU)

    if os.path.isfile(str(Path.home()) + "/.ssh/" + name + ".pub"):
        logging.info("Key pair created")
        return 0
