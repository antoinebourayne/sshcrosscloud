import os
import getpass as gt
import sys
import time
import sshcrosscloud
import logging

from sshcrosscloud import utils, libcloud_extended
from sshcrosscloud.libcloud_extended import get_provider_specific_driver
from sshcrosscloud.utils import get_string_from_file, SSHParams

"""
SSHCrossCloud Class

Basically contains all the attributes to create an instance on multiple providers and a Libcloud Driver
"""


class SSHCrossCloud:

    def __init__(self, replace_dotenv=True, replace_environ=True, **params):
        self.ssh_params = utils.SSHParams(**params)

        self.ssh_params.update_custom_values(replace_dotenv, replace_environ)

        self._init_variables()

        self.spe_driver = get_provider_specific_driver(self.ssh_params)

        self.spe_driver.init_specific_credentials()

    def _init_variables(self, ):
        """
        A la fin de la fonction, env possède le maximum de variables d'environement
        calculés, pour ne plus avoir à gérer les erreurs ou les valeurs par défaut.
        """
        # Specific to entreprise polygrams
        if not self.ssh_params.polygram:
            self.ssh_params.username = gt.getuser()
        else:
            self.ssh_params.username = self.ssh_params.polygram
        if not self.ssh_params.instance_name:
            self.ssh_params.instance_name = self.ssh_params.username.lower() + "-sshcrosscloud"
        if not self.ssh_params.rsa_key_name:
            self.ssh_params.rsa_key_name = self.ssh_params.username + "-sshcrosscloud"
        if not self.ssh_params.rsa_private_key_file_path:
            self.ssh_params.rsa_private_key_file_path = os.path.expanduser('~') + "/.ssh/" + self.ssh_params.rsa_key_name

        if not self.ssh_params.pem_ssh:
            self.ssh_params.pem_ssh = "-i " + self.ssh_params.rsa_private_key_file_path

        if self.ssh_params.verbose:
            self.ssh_params.final_state = "leave"

        self.ssh_params.user_data = get_string_from_file(self.ssh_params.user_data_file_path)

    def init_provider_specifics(self):
        nodes = self.spe_driver.init_specific()

        for node in nodes:
            if node.name == self.ssh_params.instance_name and node.state not in ["terminated"]:
                self.ssh_params.sshcrosscloud_instance_id = node.id
                self.ssh_params.instance_state = node.state
                self.ssh_params.public_ip = node.public_ips[0]

    def wait_until_initialization(self) -> int:
        """
        Tries to SSH the instance multiple times until it is initialized
        :param :
        :return: 0 if ok, else error code
        """
        logging.info("Waiting for instance initialization...")
        i = 0
        # Try to connect to instance for a few times
        while i < 10:
            logging.info("Trying to connect... (" + str(i + 1) + ")")
            try:
                # Works like a ping to know if ssh is ok
                if self.ssh_params.verbose:
                    ssh_return = "ssh " + self.ssh_params.ssh_fonctionnal_params + " -v " + self.ssh_params.pem_ssh + " " + \
                                 self.ssh_params.instance_user + "@" + self.ssh_params.public_ip + " exit && echo $?"
                else:
                    ssh_return = "ssh " + self.ssh_params.ssh_fonctionnal_params + " " + self.ssh_params.pem_ssh + " " + \
                                 self.ssh_params.instance_user + "@" + self.ssh_params.public_ip + " exit && echo $?"

                return_code = os.system(ssh_return)
                if return_code == 0:
                    logging.info("Instance is available")
                    return return_code
                elif return_code == 65280:
                    logging.info("Instance is not yet available")
                    time.sleep(5)
                    i += 1
                else:
                    return return_code

            except Exception as e:
                raise Exception(e)

        raise Exception("Couldn't connect to instance")

    def init_instance(self, with_instance) -> None:
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

        self.ssh_params.sshcrosscloud_instance_id = return_node[0].id
        self.ssh_params.public_ip = return_node[0].public_ips[0]
        return

    def manage_instance(self) -> None:
        if not self.ssh_params.sshcrosscloud_instance_id:
            self.init_instance(with_instance=False)

        if self.ssh_params.instance_state == "unknown":
            raise Exception("Instance stopping or shutting down, please try again later")

        if self.ssh_params.instance_state == "stopped":
            self.spe_driver.start_instance()
            self.init_instance(with_instance=True)

        return

    def attach_to_instance(self) -> int:
        """
        Open SSH terminal to instance and launch multiplex session if needed
        :param : self
        :return: 0 if ok, else error code
        """
        ssh_params = ""
        if self.ssh_params.ssh_params:
            ssh_params = self.ssh_params.ssh_params
        if self.ssh_params.verbose:
            ssh_params = ssh_params + " -v"
        ssh_command = "ssh " + self.ssh_params.ssh_fonctionnal_params + " " + ssh_params + " " + self.ssh_params.pem_ssh + " " \
                      + self.ssh_params.instance_user + "@" + self.ssh_params.public_ip + " "
        if not self.ssh_params.multiplex:
            if self.ssh_params.ssh_script:
                logging.info("ssh script : " + ssh_command + self.ssh_params.ssh_script)
                return_code = os.system(ssh_command + self.ssh_params.ssh_script)
            else:
                logging.info("no ssh script : " + ssh_command)
                return_code = os.system(ssh_command)

            return return_code
        else:
            if self.ssh_params.ssh_detach:
                if self.ssh_params.ssh_script:
                    multiplex_command = ssh_command + " -t 'tmux has-session -t " + self.ssh_params.instance_name \
                                        + " || tmux new-session -s " + self.ssh_params.instance_name + " -d" \
                                        + ' "' + self.ssh_params.ssh_script + '"' + "'"
                else:
                    multiplex_command = ssh_command + " -t 'tmux has-session -t " + self.ssh_params.instance_name \
                                        + " || tmux new-session -s " + self.ssh_params.instance_name + " -d'"
                logging.info("--detach : " + multiplex_command)
                return_code = os.system(multiplex_command)

                return return_code

            elif self.ssh_params.ssh_attach:
                # ssh arg "-t" forces to allocate a terminal, does not not otherwise
                if self.ssh_params.ssh_script:
                    multiplex_command = ssh_command + " -t 'tmux attach-session -t " + self.ssh_params.instance_name \
                                        + " || tmux new-session -s " + self.ssh_params.instance_name \
                                        + ' "' + self.ssh_params.ssh_script + '"' + "'"
                else:
                    multiplex_command = ssh_command + " -t 'tmux attach-session -t " + self.ssh_params.instance_name \
                                        + " || tmux new-session -s " + self.ssh_params.instance_name + "'"
                logging.info("--attach : " + multiplex_command)
                return_code = os.system(multiplex_command)

                return return_code

    def finish_action(self) -> None:
        """
        Terminates, destroys or leaves instances depending on the FINAL_STATE
        :param : self
        :return: None
        """
        if self.ssh_params.final_state == "leave":
            logging.warning("Your instance is still alive")
            return
        if self.ssh_params.verbose == "y":
            logging.warning("Instance final state : " + self.ssh_params.final_state)
            return
        if self.ssh_params.nbOfSshConnections < 2:
            if self.ssh_params.final_state == "stop":
                logging.warning("Stopping instances...")
                self.spe_driver.stop_instance()
            elif self.ssh_params.final_state == "terminate":
                logging.warning("Terminating instances...")
                self.spe_driver.terminate_instance()
            else:
                if self.ssh_params.nbOfSshConnections > 1:
                    self.ssh_params.final_state = "leave"
                    logging.warning("Another connection to EC2 instance is alive. The AWS EC2 instance is active")
                else:
                    logging.warning("Instance " + self.ssh_params.instance_name + " is alive")
            return

    def rsync_to_instance(self) -> int:
        """
        Using rsync in command line to sync local directory to instance
        :param : self
        :return: 0 if ok, else error code
        """
        logging.info("Synchronizing local directory to instance")
        if self.ssh_params.verbose:
            command = "rsync -Pav -e 'ssh " + self.ssh_params.ssh_fonctionnal_params + " " + self.ssh_params.pem_ssh \
                      + "'" + " --exclude-from='.rsyncignore' " + self.ssh_params.rsync_directory + "/* " + \
                      self.ssh_params.instance_user + "@" + self.ssh_params.public_ip + ":/home/" + self.ssh_params.instance_user
        else:
            command = "rsync -Pa -e 'ssh " + self.ssh_params.ssh_fonctionnal_params + " " + self.ssh_params.pem_ssh \
                      + "'" + " --exclude-from='.rsyncignore' " + self.ssh_params.rsync_directory + "/* " + \
                      self.ssh_params.instance_user + "@" + self.ssh_params.public_ip + ":/home/" + self.ssh_params.instance_user
        return_code = os.system(command)

        return return_code

    def rsync_back_to_local(self) -> int:
        """
        Rsync back
        :param : self
        :return: 0 if ok, else error code
        """
        logging.info("Synchronizing directory back to local")
        if self.ssh_params.verbose:
            command = "rsync -vzaP -r -e 'ssh -o StrictHostKeyChecking=no -o LogLevel=quiet " + self.ssh_params.pem_ssh \
                      + "' " + self.ssh_params.instance_user + "@" + self.ssh_params.public_ip + \
                      ":/home/" + self.ssh_params.instance_user + "/*" + " " + self.ssh_params.rsync_directory
        else:
            command = "rsync -zaP -r -e 'ssh -o StrictHostKeyChecking=no -o LogLevel=quiet " + self.ssh_params.pem_ssh \
                      + "' " \
                      + self.ssh_params.instance_user + "@" + self.ssh_params.public_ip + \
                      ":/home/" + self.ssh_params.instance_user + "/*" + " " + self.ssh_params.rsync_directory
        return_code = os.system(command)

        return return_code

    def check_parameters(self):
        """
        Check that the parameters have only one action and one final state
        :return:
        """
        if not self.ssh_params.provider:
            raise Exception("You must chose a provider (aws, azure or gcp)")
        list_final_state = (self.ssh_params.leave, self.ssh_params.stop, self.ssh_params.terminate)
        if sum(list_final_state) > 1:
            raise Exception("Can't have multiple final states")
        list_actions = (self.ssh_params.detach, self.ssh_params.attach, self.ssh_params.finish)
        if sum(list_actions) > 1:
            raise Exception("Can't have multiple actions")

    def manage_commands(self):
        if self.ssh_params.leave:
            self.ssh_params.final_state = "leave"

        if self.ssh_params.stop:
            self.ssh_params.final_state = "stop"

        if self.ssh_params.terminate:
            self.ssh_params.final_state = "terminate"

        if self.ssh_params.detach:
            self.ssh_params.final_state = "leave"
            self.ssh_params.ssh_detach = True
            self.ssh_params.multiplex = True

        if self.ssh_params.attach:
            self.ssh_params.final_state = "leave"
            self.ssh_params.ssh_attach = True
            self.ssh_params.multiplex = True
            self.ssh_params.no_rsync_begin = True
            self.ssh_params.no_rsync_end = True

        if self.ssh_params.finish:
            self.ssh_params.no_rsync_begin = True

        if self.ssh_params.norsync:
            self.ssh_params.no_rsync_begin = True
            self.ssh_params.no_rsync_end = True

        if self.ssh_params.provider:
            self.ssh_params.provider = self.ssh_params.provider

        if self.ssh_params.l:
            self.ssh_params.ssh_params = self.ssh_params.ssh_params + " -L " + self.ssh_params.l

        if self.ssh_params.r:
            self.ssh_params.ssh_params = self.ssh_params.ssh_params + " -R " + self.ssh_params.r

        if self.ssh_params.i:
            self.ssh_params.pem_ssh = "-i " + self.ssh_params.i

        if self.ssh_params.verbose:
            self.ssh_params.verbose = True

        if self.ssh_params.status:
            self.ssh_params.status_mode = True
            self.ssh_params.no_rsync_begin = True
            self.ssh_params.no_rsync_end = True
            self.ssh_params.no_attach = True
            self.ssh_params.display_nodes = True
            self.ssh_params.no_wait_until_init = True

        if self.ssh_params.destroy:
            self.ssh_params.no_rsync_begin = True
            self.ssh_params.no_rsync_end = True
            self.ssh_params.no_attach = True
            self.ssh_params.final_state = "terminate"

    def execute(self, sshscript=None):
        if sshscript:
            self.ssh_params.sshscript = sshscript

        # Only once the credentials are initialized, this method can be called
        self.init_provider_specifics()

        self.check_parameters()

        self.manage_commands()

        # Main process
        if self.ssh_params.display_nodes:
            self.spe_driver.display_instances()

        if not self.ssh_params.status_mode:
            self.manage_instance()

        if not self.ssh_params.no_wait_until_init:
            wait_until_initialization = self.wait_until_initialization()
            if wait_until_initialization != 0:
                raise Exception("An error has occured while executing ssh whith code : "
                                + str(wait_until_initialization))

        if not self.ssh_params.no_rsync_begin:
            rsync_to_instance = self.rsync_to_instance()
            if rsync_to_instance != 0:
                raise Exception("An error has occured while executing rsync to instance whith code : "
                                + str(rsync_to_instance))

        if not self.ssh_params.no_attach:
            attach_to_instance = self.attach_to_instance()
            if attach_to_instance != 0:
                raise Exception("An error has occured while executing ssh whith code : " + str(attach_to_instance))

        if not self.ssh_params.no_rsync_end:
            rsync_back_to_local = self.rsync_back_to_local()
            if rsync_back_to_local != 0:
                raise Exception("An error has occured while executing rsync back to local whith code : "
                                + str(rsync_back_to_local))

        if not self.ssh_params.status_mode:
            self.finish_action()
