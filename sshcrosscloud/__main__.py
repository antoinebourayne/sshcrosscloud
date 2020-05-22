import getpass as gt
import subprocess
import time
import logging
from pathlib import Path
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud
from libcloud.compute.base import NodeAuthSSHKey
import os
import sys
from libcloud_extended.configure import ec2configure
from argparse import ArgumentParser
from sshcrosscloud.providers_specifics import get_provider_specific
from sshcrosscloud.utils import get_public_key

"""

SSH-CROSS-CLOUD

"""

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
parser.add_argument('-v', action='store_true')

# VALUES
parser.add_argument('--provider', default=None, const=None)
parser.add_argument('-L', default=None, const=None)
parser.add_argument('-R', default=None, const=None)
parser.add_argument('-i', default=None, const=None)

args = parser.parse_args()


# MAIN
def main():
    # PPR : par exemple, tester des combinaisons mauvaises de paramètres comme --attach --detach --finish dans la même commande.
    # PPR : il faut également tester les bonnes combinaisons.
    pre_env = os.environ
    arg = parser.parse_args()

    # SSH Script
    if parser.parse_args().sshscript:
        pre_env["SSH_SCRIPT"] = arg.sshscript

    # Arguments
    if arg.leave:
        arg_leave(pre_env)

    if arg.stop:
        arg_stop(pre_env)

    if arg.terminate:
        arg_terminate(pre_env)

    if arg.detach:
        arg_detach(pre_env)

    if arg.attach:
        arg_attach(pre_env)

    if arg.finish:
        arg_finish(pre_env)

    if arg.verbose:
        arg_verbose(pre_env)

    if arg.norsync:
        arg_no_rsync(pre_env)

    if arg.provider:
        arg_provider(pre_env, arg.provider)
    else:
        logging.warning("You must chose a provider (aws, azure or gcp)")
        sys.exit(0)

    if arg.L:
        arg_L(pre_env, arg.L)

    if arg.R:
        arg_R(pre_env, arg.R)

    if arg.i:
        arg_i(pre_env, arg.i)

    if arg.v:
        arg_v()

    if arg.debug:
        arg_debug(pre_env)

    if arg.config:
        arg_config(pre_env)

    if arg.status:
        arg_status()

    if arg.destroy:
        arg_destroy()

    """-----------------Here call methods---------------------"""
    logging.info('-----SSH CROSS CLOUD-----')

    # Credentials
    if pre_env.get('CONFIG'):
        set_credentials()

    # SSH Object
    ssh = SSHCrossCloud(pre_env)

    # Auto config
    if pre_env.get('CONFIG'):
        provider_config(ssh)

    # TODO: gérer les différents displays
    # display_aws_instance_characteristics(ssh)

    # If no instance found, create one
    if not ssh.env.get("INSTANCE_ID"):
        if create_instance(ssh) != 0:
            sys.exit(0)
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


# Getters and inits

def set_credentials():  # PPR: devrait s'appeler set_credentials AWS ?
    if os.path.isfile(str(Path.home()) + "/.aws/credentials"):  # PPR: tu n'est pas multi provider ici !
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
def arg_leave(pre_env):
    pre_env["FINAL_STATE"] = "leave"


def arg_stop(pre_env):
    if pre_env.get("SSH_DETACH") != "y" and pre_env.get("SSH_ATTACH") != "y":
        pre_env["FINAL_STATE"] = "stop"


def arg_terminate(pre_env):
    if pre_env.get("SSH_DETACH") != "y" and pre_env.get("SSH_ATTACH") != "y":
        pre_env["FINAL_STATE"] = "terminate"


def arg_detach(pre_env):
    pre_env["FINAL_STATE"] = "leave"
    pre_env["SSH_DETACH"] = "y"
    pre_env["MULTIPLEX"] = "y"


def arg_attach(pre_env):
    pre_env["MULTIPLEX"] = "y"
    pre_env["SSH_ATTACH"] = "y"
    pre_env["FINAL_STATE"] = "leave"
    pre_env["NO_RSYNC_BEGIN"] = "y"
    pre_env["NO_RSYNC_END"] = "y"


def arg_finish(pre_env):
    pre_env["NO_RSYNC_BEGIN"] = "y"


def arg_config(pre_env):
    # guide_credentials(pre_env["PROVIDER"])
    pre_env["CONFIG"] = "y"


def arg_destroy():
    ssh = SSHCrossCloud()
    terminate_instance(ssh)
    sys.exit(0)


def arg_provider(pre_env, arg: str):
    pre_env['PROVIDER'] = arg.upper()


def arg_debug(pre_env):
    pre_env['DEBUG'] = "y"


def arg_L(pre_env, arg):
    if pre_env.get('SSH_PARAMS'):
        pre_env["SSH_PARAMS"] = pre_env["SSH_PARAMS"] + " -L " + arg
    else:
        pre_env["SSH_PARAMS"] = " -L " + arg


def arg_R(pre_env, arg):
    if pre_env.get('SSH_PARAMS'):
        pre_env["SSH_PARAMS"] = pre_env["SSH_PARAMS"] + " -R " + arg
    else:
        pre_env["SSH_PARAMS"] = " -R " + arg


def arg_i(pre_env, arg):
    pre_env["PEM_SSH"] = "-i " + arg


def arg_v():
    logging.getLogger().setLevel(logging.INFO)


def arg_no_rsync(pre_env):
    pre_env['NO_RSYNC_BEGIN'] = "y"
    pre_env['NO_RSYNC_END'] = "y"


def arg_verbose(pre_env):
    pre_env['RSYNC_VERBOSE'] = "y"


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


def create_instance(ssh: SSHCrossCloud) -> int:
    """
    Creates an instance based on the parameters
    :param ssh:
    :return: 0 if created and ip exists, 1 if error
    """
    logging.info("Creating instance...")

    spe_driver = get_provider_specific(ssh)
    node = spe_driver.create_instance()

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
