import getpass as gt
import subprocess
import time
import logging
from pathlib import Path
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud
import os
import sys
from argparse import ArgumentParser
from sshcrosscloud.libcloud_extended import get_provider_specific_driver, ProviderSpecific
import sshcrosscloud.utils as utils

"""

SSH-CROSS-CLOUD

"""

# TODO: remplir les "help"
# TODO: couleurs pour les logs
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
arg_dict = vars(args)


# MAIN
def main():
    pre_env = os.environ

    # SSH Script
    if parser.parse_args().sshscript:
        pre_env["SSH_SCRIPT"] = args.sshscript

    # Arguments
    if args.leave:
        arg_leave(pre_env)

    if args.stop:
        arg_stop(pre_env)

    if args.terminate:
        arg_terminate(pre_env)

    if args.detach:
        arg_detach(pre_env)

    if args.attach:
        arg_attach(pre_env)

    if args.finish:
        arg_finish(pre_env)

    if args.verbose:
        arg_verbose(pre_env)

    if args.norsync:
        arg_no_rsync(pre_env)

    if args.provider:
        arg_provider(pre_env, args.provider)
    else:
        logging.warning("You must chose a provider (aws, azure or gcp)")
        sys.exit(0)

    if args.L:
        arg_L(pre_env, args.L)

    if args.R:
        arg_R(pre_env, args.R)

    if args.i:
        arg_i(pre_env, args.i)

    if args.v:
        arg_v()

    if args.debug:
        arg_debug(pre_env)

    if args.config:
        arg_config(pre_env)

    if args.status:
        arg_status(pre_env)

    if args.destroy:
        arg_destroy(pre_env)

    """-----------------Here call methods---------------------"""
    logging.info('-----SSH CROSS CLOUD-----')

    # Credentials
    if pre_env.get('CONFIG'):
        utils.set_credentials(pre_env['PROVIDER'])

    # SSH Object
    ssh = SSHCrossCloud(pre_env, arg_dict)

    # Auto config
    if pre_env.get('CONFIG'):
        provider_config(ssh)

    # Specific Driver
    spe_driver = get_provider_specific_driver(ssh)

    # TODO: gérer les différents displays
    # display_aws_instance_characteristics(ssh)

    # If no instance found, create one
    if not ssh.env.get("INSTANCE_ID"):
        if wait_for_public_ip(ssh, spe_driver.create_instance()) != 0:
            raise Exception("Could not create instance")
    elif ssh.env.get("INSTANCE_STATE") == "unknown":
        raise Exception("Instance stopping or shutting down, please try again later")
    elif ssh.env.get("INSTANCE_STATE") == "stopped":
        if start_instance(ssh) != 0:
            raise Exception("Could not start instance")
        wait_for_public_ip(ssh, get_node(ssh))

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


def provider_config(ssh: SSHCrossCloud):
    if os.path.isfile(str(Path.home()) + "/.ssh" + ssh.env['USERNAME']):
        # AWS
        if ssh.env['PROVIDER'] == 'AWS':
            if ssh.env['USERNAME'] in ssh.driver.ex_list_keypairs():
                logging.info("Key pair already stored, ignoring step")
            else:
                utils.create_local_rsa_key_pair(ssh.env['USERNAME'])
        # Other Providers
        else:
            if os.path.isfile(str(Path.home()) + "/.ssh" + ssh.env['USERNAME'] + ".pub"):
                logging.info("Key pairs already stored, ignoring step")
            else:
                utils.create_local_rsa_key_pair(ssh.env['USERNAME'])
    else:
        utils.create_local_rsa_key_pair(ssh.env['USERNAME'])


def guide_credentials(provider: str):
    if provider == 'AWS':
        guide = utils.guide_aws
    elif provider == 'AZURE':
        guide = utils.guide_azure
    elif provider == 'GCP':
        guide = utils.guide_gcp
    else:
        guide = "No guide for this provider"

    logging.info(guide)


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


def arg_destroy(pre_env):
    ssh = SSHCrossCloud(pre_env, arg_dict)
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


def arg_status(pre_env):
    ssh = SSHCrossCloud(pre_env, arg_dict)
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


def get_node(ssh: SSHCrossCloud):
    if ssh.env['PROVIDER'] == "AZURE":
        nodes = ssh.driver.list_nodes(ssh.env['AZ_RESOURCE_GROUP'])
    else:
        nodes = ssh.driver.list_nodes()
    if ssh.env.get('INSTANCE_ID'):
        for node in nodes:
            if node.id == ssh.env['INSTANCE_ID']:
                return node


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


def wait_for_public_ip(ssh: SSHCrossCloud, node):
    logging.info("Initializating instance...")
    nodes = [node]

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


def start_instance(ssh: SSHCrossCloud):
    """
    Starts a stopped instance
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
        if node.id == ssh.env['INSTANCE_ID'] and node.state == "stopped":
            start = ssh.driver.ex_start_node(node)
            if start:
                logging.info("Started : " + node.id)
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
