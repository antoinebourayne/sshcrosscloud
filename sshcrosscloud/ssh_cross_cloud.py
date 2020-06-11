import os
import getpass as gt
import subprocess
import sys
from pathlib import Path
import configparser
import time
import getpass
from dotenv import find_dotenv, dotenv_values
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
import logging

from sshcrosscloud.libcloud_extended import get_provider_specific_driver
from sshcrosscloud.utils import get_string_from_file, SSHVar

"""
SSHCrossCloud Class

Basically contains all the attributes to create an instance on multiple providers and a Libcloud Driver
"""


# TODO: tout ce qui est specific, ajouter dans libcloud extended

class SSHCrossCloud:
    def __init__(self, ssh_vars: SSHVar):
        self.driver = None
        self.ssh_vars = ssh_vars

        # Check that the parameters have only one action and one final state
        self._check_parameters()

        # dotenv values are taken form .env file
        self._init_env(dotenv_values(find_dotenv()), os.environ)

        self._init_variables()

        self.spe_driver = get_provider_specific_driver(self.ssh_vars)

    def _init_env(self, dotenv, environ):
        """
        This method creates a dict with dotenv values updated by the environment values,
        then store them in the ssh_var object
        """
        # Default
        env = {}

        # Dotenv
        for k, v in dotenv.items():
            env[k] = v

        # OS Environ
        for k, v in environ.items():
            env[k] = v

        # Replace attributes that where declared in the env or dotenv
        for attr, value in self.ssh_vars.__dict__.items():
            if env.get(attr.upper()):
                setattr(self.ssh_vars, attr, env.get(attr.upper()))

    def _init_variables(self):
        """
        A la fin de la fonction, env possède le maximum de variables d'environement
        calculés, pour ne plus avoir à gérer les erreurs ou les valeurs par défaut.
        """
        # Specific to entreprise polygrams
        if not self.ssh_vars.polygram:
            self.ssh_vars.username = gt.getuser()
        else:
            self.ssh_vars.username = self.ssh_vars.polygram
        if not self.ssh_vars.instance_name:
            self.ssh_vars.instance_name = self.ssh_vars.username.lower() + "-sshcrosscloud"

        # TODO: take care of this
        # if not self.env.get('AWS_RSYNC_DIR'):
        #     self.env['AWS_RSYNC_DIR'] = os.getcwd()

        if not self.ssh_vars.pem_ssh:
            self.ssh_vars.pem_ssh = "-i " + str(Path.home()) + "/.ssh/" + self.ssh_vars.username

        if self.ssh_vars.debug:
            self.ssh_vars.final_state = "leave"

        self.ssh_vars.user_data = get_string_from_file(".user_data")

    def _check_parameters(self):
        if not self.ssh_vars.provider:
            raise Exception("You must chose a provider (aws, azure or gcp)")
        list_final_state = (
            self.ssh_vars.arg_dict['leave'], self.ssh_vars.arg_dict['stop'], self.ssh_vars.arg_dict['terminate'])
        if sum(list_final_state) > 1:
            raise Exception("Can't have multiple final states")
        list_actions = (
            self.ssh_vars.arg_dict['detach'], self.ssh_vars.arg_dict['attach'], self.ssh_vars.arg_dict['finish'])
        if sum(list_actions) > 1:
            raise Exception("Can't have multiple actions")

    def init_provider_specifics(self):
        """
        AWS EC2  : AWS
        Azure VM : AZURE
        Google Compute Engine : GCP
        :param env:
        """
        try:
            if self.ssh_vars.provider == "aws":
                default_user_list = self.ssh_vars.aws.default_user_list
                for i, j in default_user_list.items():
                    if i.lower() in self.ssh_vars.aws.image_name.lower():
                        self.ssh_vars.instance_user = j

                self.ssh_vars.credentials_items = self.ssh_vars.aws.credentials_items
                self.ssh_vars.credentials_file_path = self.ssh_vars.aws.credentials_path

                if not self.ssh_vars.aws.region:
                    self.ssh_vars.aws.region = get_aws_region(self.ssh_vars.aws.credentials_path)
                self.ssh_vars.aws.access_key_id, self.ssh_vars.aws.secret_access_key = get_credentials(
                    self.ssh_vars.credentials_file_path, self.ssh_vars.provider)

                cls = get_driver(Provider.EC2)
                provider_driver = cls(self.ssh_vars.aws.access_key_id,
                                      self.ssh_vars.aws.secret_access_key,
                                      region=self.ssh_vars.aws.region)

                self.driver = provider_driver
                nodes = self.driver.list_nodes()

            elif self.ssh_vars.provider == "azure":
                self.ssh_vars.instance_user = "azure"

                self.ssh_vars.credentials_items = self.ssh_vars.azure.credentials_items
                self.ssh_vars.credentials_file_path = self.ssh_vars.azure.credentials_path

                if not self.ssh_vars.azure.region:
                    raise Exception("No region found, you must specify a region in .env file")
                self.ssh_vars.azure.tenat_id, self.ssh_vars.azure.subscription_id, self.ssh_vars.azure.application_id, \
                self.ssh_vars.azure.secret = get_credentials(self.ssh_vars.credentials_file_path,
                                                             self.ssh_vars.provider)
                if not self.ssh_vars.azure.public_ip_name:
                    self.ssh_vars.azure.public_ip_name = "sshcrosscloud-ip-" + self.ssh_vars.username
                if not self.ssh_vars.azure.virtual_network:
                    self.ssh_vars.azure.virtual_network = "sshcrosscloud-vn-" + self.ssh_vars.username
                if not self.ssh_vars.azure.subnet:
                    self.ssh_vars.azure.subnet = "sshcrosscloud-sn-" + self.ssh_vars.username

                cls = get_driver(Provider.AZURE_ARM)
                provider_driver = cls(tenant_id=self.ssh_vars.azure.tenat_id,
                                      subscription_id=self.ssh_vars.azure.subscription_id,
                                      key=self.ssh_vars.azure.application_id,
                                      secret=self.ssh_vars.azure.secret)

                self.driver = provider_driver
                nodes = self.driver.list_nodes(self.ssh_vars.azure.resource_group)

            elif self.ssh_vars.provider == "gcp":
                self.ssh_vars.instance_user = getpass.getuser()

                self.ssh_vars.credentials_items = self.ssh_vars.gcp.credentials_items
                self.ssh_vars.credentials_file_path = self.ssh_vars.gcp.credentials_path

                if not self.ssh_vars.gcp.region:
                    raise Exception("No region found, you must specify a region in .env file")
                self.ssh_vars.gcp.user_id, self.ssh_vars.gcp.key_path, self.ssh_vars.gcp.project, self.ssh_vars.gcp.data_center \
                    = get_credentials(self.ssh_vars.credentials_file_path, self.ssh_vars.provider)

                cls = get_driver(Provider.GCE)
                provider_driver = cls(user_id=self.ssh_vars.gcp.user_id,
                                      key=self.ssh_vars.gcp.key_path,
                                      project=self.ssh_vars.gcp.project,
                                      datacenter=self.ssh_vars.gcp.data_center)

                self.driver = provider_driver
                nodes = self.driver.list_nodes()

            else:
                raise Exception("Provider not supported")

            for node in nodes:
                # TODO: manage other states (ex: shutting down)
                if node.name == self.ssh_vars.instance_name and node.state not in ["terminated"]:
                    self.ssh_vars.instance_id = node.id
                    self.ssh_vars.instance_state = node.state
                    self.ssh_vars.public_ip = node.public_ips[0]

        except:
            raise Exception("Could not get driver")

    def wait_until_initialization(self) -> None:
        """
        Tries to SSH the instance multiple times until it is initialized
        :param ssh:
        :return:0 if OK 1 if error 2 if no instance
        """
        if not self.ssh_vars.no_wait_until_init:
            logging.info("Waiting for instance initialization...")
            i = 0

            # Try to connect to instance for a few times
            while i < 10:
                logging.info("Trying to connect... (" + str(i + 1) + ")")
                try:
                    # Works like a ping to know if ssh is ok

                    if self.ssh_vars.debug:
                        ssh_return = "ssh " + self.ssh_vars.ssh_default_params + " -v " + self.ssh_vars.pem_ssh + " " + \
                                     self.ssh_vars.instance_user + "@" + self.ssh_vars.public_ip + " exit && echo $?"
                    else:
                        ssh_return = "ssh " + self.ssh_vars.ssh_default_params + " " + self.ssh_vars.pem_ssh + " " + \
                                     self.ssh_vars.instance_user + "@" + self.ssh_vars.public_ip + " exit && echo $?"

                    output_test = subprocess.check_output(ssh_return, shell=True)
                    #TODO: get the output that s not clean

                    # if '0' not in output_test:
                    #     raise Exception("An error occured while attempting ssh to instance")

                    logging.info("Instance is available")

                    return

                except subprocess.CalledProcessError:
                    logging.info("Instance is not yet available")

                time.sleep(5)
                i += 1

            raise Exception("Could not connect to instance, please try later")

    def wait_for_public_ip(self, with_instance) -> None:
        logging.info("Initializating instance...")

        if with_instance:
            node = self.spe_driver.get_node()
        else:
            node = self.spe_driver.create_instance()

        nodes = [node]

        # Azure needs a specified resource group
        return_node = self.spe_driver.spe_wait_until_running(nodes)

        if not return_node[0].public_ips:
            raise Exception("No public IP available")

        self.ssh_vars.instance_id = return_node[0].id
        self.ssh_vars.public_ip = return_node[0].public_ips[0]

        return

    def manage_instance(self) -> None:
        if not self.ssh_vars.status_mode:
            # If no instance found, create one
            if not self.ssh_vars.instance_id:  # TODO: si jamais deja dans l'env ??
                if self.wait_for_public_ip(with_instance=False):
                    raise Exception("Could not create instance")
            if self.ssh_vars.instance_state == "unknown":
                raise Exception("Instance stopping or shutting down, please try again later")
            elif self.ssh_vars.instance_state == "stopped":
                if self.spe_driver.start_instance() != 0:
                    raise Exception("Could not start instance")
                self.wait_for_public_ip(with_instance=True)

    def attach_to_instance(self) -> None:
        """
        Open SSH terminal to instance and launch multiplex session if needed
        :param ssh:
        :return: 0 if SSH connection succeeded, 1 if not
        """
        if not self.ssh_vars.no_attach:

            ssh_params = ""

            if self.ssh_vars.ssh_params:
                ssh_params = self.ssh_vars.ssh_params
            if self.ssh_vars.debug:
                ssh_params = ssh_params + " -v"

            ssh_command = "ssh " + self.ssh_vars.ssh_default_params + ssh_params + " " + self.ssh_vars.pem_ssh + " " \
                          + self.ssh_vars.instance_user + "@" + self.ssh_vars.public_ip + " "

            if not self.ssh_vars.multiplex:
                if self.ssh_vars.ssh_script:
                    logging.info("ssh script : " + ssh_command + self.ssh_vars.ssh_script)
                    #output_test = subprocess.check_output(ssh_command + self.ssh_vars.ssh_script, shell=True)
                    os.system(ssh_command + self.ssh_vars.ssh_script)
                    # if output_test != 0:
                    #     raise Exception("An error occured while attempting ssh to instance")

                else:
                    logging.info("no ssh script : " + ssh_command)
                    #output_test = subprocess.check_output(ssh_command, shell=True)
                    os.system(ssh_command)
                    # if output_test != 0:
                    #     raise Exception("An error occured while attempting ssh to instance")
                return
            else:
                if self.ssh_vars.ssh_detach:
                    if self.ssh_vars.ssh_script:
                        multiplex_command = ssh_command + " -t 'tmux has-session -t " + self.ssh_vars.instance_name \
                                            + " || tmux new-session -s " + self.ssh_vars.instance_name + " -d" \
                                            + ' "' + self.ssh_vars.ssh_script + '"' + "'"
                    else:
                        multiplex_command = ssh_command + " -t 'tmux has-session -t " + self.ssh_vars.instance_name \
                                            + " || tmux new-session -s " + self.ssh_vars.instance_name + " -d'"

                    logging.info("--detach : " + multiplex_command)
                    # output_test = subprocess.check_output(multiplex_command, shell=True)
                    os.system(multiplex_command)
                    # if output_test != 0:
                    #     raise Exception("An error occured while attempting ssh and tmux to instance")

                    return

                elif self.ssh_vars.ssh_attach:
                    # ssh arg "-t" forces to allocate a terminal, does not not otherwise
                    if self.ssh_vars.ssh_script:
                        multiplex_command = ssh_command + " -t 'tmux attach-session -t " + self.ssh_vars.instance_name \
                                            + " || tmux new-session -s " + self.ssh_vars.instance_name \
                                            + ' "' + self.ssh_vars.ssh_script + '"' + "'"
                    else:
                        multiplex_command = ssh_command + " -t 'tmux attach-session -t " + self.ssh_vars.instance_name \
                                            + " || tmux new-session -s " + self.ssh_vars.instance_name + "'"

                    logging.info("--attach : " + multiplex_command)
                    # output_test = subprocess.check_output(multiplex_command, shell=True)
                    os.system(multiplex_command)
                    # if output_test != 0:
                    #     raise Exception("An error occured while attempting ssh to instance")

                    return

    def finish_action(self) -> None:
        """
        Terminates, destroys or leaves instances depending on the FINAL_STATE
        :param ssh:
        :return:0 if OK 1 if error
        """
        if not self.ssh_vars.status_mode:
            if self.ssh_vars.final_state == "leave":
                logging.warning("Your instance is still alive")
                return

            if self.ssh_vars.debug == "y":
                logging.warning("Instance final state : " + self.ssh_vars.final_state)
                return

            if self.ssh_vars.nbOfSshConnections < 2:

                if self.ssh_vars.final_state == "stop":
                    logging.warning("Stopping instances...")
                    self.spe_driver.stop_instance()

                elif self.ssh_vars.final_state == "terminate":
                    logging.warning("Terminating instances...")
                    self.spe_driver.terminate_instance()

                else:
                    if self.ssh_vars.nbOfSshConnections > 1:
                        self.ssh_vars.final_state = "leave"
                        logging.warning("Another connection to EC2 instance is alive. The AWS EC2 instance is active")
                    else:
                        logging.warning("The AWS EC instance " + self.ssh_vars.instance_name + " is alive")

                return

    def rsync_to_instance(self) -> None:
        """
        Using rsync in command line to sync local directory to instance
        :param ssh:
        :return:
        """
        if self.ssh_vars.no_rsync_begin:
            logging.info("No rsync to instance")
        else:
            logging.info("Synchronizing local directory to instance")
            if self.ssh_vars.rsync_verbose:
                command = "rsync -Pav -e 'ssh " + self.ssh_vars.ssh_default_params + " " + self.ssh_vars.pem_ssh \
                          + "'" + " --exclude-from='.rsyncignore' $HOME/* " + \
                          self.ssh_vars.instance_user + "@" + self.ssh_vars.public_ip + ":/home/" + self.ssh_vars.instance_user
            else:
                command = "rsync -Pa -e 'ssh " + self.ssh_vars.ssh_default_params + " " + self.ssh_vars.pem_ssh \
                          + "'" + " --exclude-from='.rsyncignore' $HOME/* " + \
                          self.ssh_vars.instance_user + "@" + self.ssh_vars.public_ip + ":/home/" + self.ssh_vars.instance_user

            os.system(command)
            #output_test = subprocess.check_output(command, shell=True)
            # TODO: idem
            # if output_test != 0:
            #     raise Exception("An error occured while attempting ssh to instance")

        return

    def rsync_back_to_local(self) -> None:
        """
        Rsync back
        :param ssh:
        :return:
        """
        if self.ssh_vars.no_rsync_end:
            logging.info("No rsync back to local")
        else:
            logging.info("Synchronizing directory back to local")
            if self.ssh_vars.rsync_verbose:
                command = "rsync -vzaP -r -e 'ssh -o StrictHostKeyChecking=no -o LogLevel=quiet " + self.ssh_vars.pem_ssh \
                          + "' " + self.ssh_vars.instance_user + "@" + self.ssh_vars.public_ip + \
                          ":/home/" + self.ssh_vars.instance_user + "/*" + " $HOME"
            else:
                command = "rsync -zaP -r -e 'ssh -o StrictHostKeyChecking=no -o LogLevel=quiet " + self.ssh_vars.pem_ssh \
                          + "' " \
                          + self.ssh_vars.instance_user + "@" + self.ssh_vars.public_ip + \
                          ":/home/" + self.ssh_vars.instance_user + "/*" + " $HOME"

            #output_test = subprocess.check_output(command, shell=True)
            os.system(command)
            # if output_test != 0:
            #     raise Exception("An error occured while attempting ssh to instance")

        return


def get_aws_region(path: str):
    if os.path.isfile(path):

        config = configparser.ConfigParser()
        config.read(path)
        aws_region = config['default']['region']

        return aws_region
    else:
        raise Exception("No region found in " + path + ", run sshcrosscloud --config -- provider aws")


def get_credentials(path: str, provider: str):
    # TODO: put in specifics
    if provider == 'aws':
        if os.path.isfile(path):

            config = configparser.ConfigParser()
            config.read(path)
            aws_access_key_id = config['default']['aws_access_key_id']
            aws_secret_access_key = config['default']['aws_secret_access_key']

            return aws_access_key_id, aws_secret_access_key
        else:
            raise Exception("No credentials found in " + path +
                            ", run sshcrosscloud --config -- provider aws")

    elif provider == 'azure':
        if os.path.isfile(path):

            config = configparser.ConfigParser()
            config.read(path)
            tenant_id = config['default']['tenant']
            subscription_id = config['default']['subscription_id']
            client_id = config['default']['client_id']
            secret = config['default']['secret']

            return tenant_id, subscription_id, client_id, secret
        else:
            raise Exception(
                "No credentials found in " + path + ", run sshcrosscloud --config -- provider azure")

    elif provider == 'gcp':
        # TODO: different methods : json https://cloud.google.com/docs/authentication/production?hl=fr#auth-cloud-explicit-python
        if os.path.isfile(path):
            config = configparser.ConfigParser()
            config.read(path)
            user_id = config['default']['user_id']
            key = config['default']['key']
            project = config['default']['project']
            datacenter = config['default']['datacenter']

            return user_id, key, project, datacenter
        else:
            raise Exception(
                "No credentials found in " + path + ", run sshcrosscloud --config -- provider gcp")

    else:
        raise Exception("Provider not supported")
