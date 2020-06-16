import os
import sys

from dotenv import dotenv_values, find_dotenv

from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud
from argparse import ArgumentParser
import sshcrosscloud.utils as utils

"""

SSH-CROSS-CLOUD

"""

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


# MAIN
def main():
    # Module Arguments
    command_args = vars(parser.parse_args())

    # Object that contains all the variables
    ssh_vars = utils.SSHVar(command_args)

    # Object that contains methods related to ssh actions and a Specific Driver with provider specific actions
    ssh = SSHCrossCloud(ssh_vars, dotenv_values(find_dotenv()), os.environ)

    if ssh.ssh_vars.config:
        # You can add here your own method to get your credentials
        ssh.spe_driver.write_credentials(utils.get_ui_credentials(
            path=ssh.ssh_vars.rsa_key_file_path,
            credentials_items=ssh.ssh_vars.credentials_items))
    # Only once the credentials are initialized, this method can be called
    ssh.init_provider_specifics()

    ssh.execute(provider=ssh.ssh_vars.provider,
                sshscript=ssh.ssh_vars.ssh_script,
                leave=ssh.ssh_vars.leave,
                stop=ssh.ssh_vars.stop,
                terminate=ssh.ssh_vars.terminate,
                detach=ssh.ssh_vars.detach,
                attach=ssh.ssh_vars.attach,
                finish=ssh.ssh_vars.finish,
                verbose=ssh.ssh_vars.verbose,
                norsync=ssh.ssh_vars.norsync,
                l=ssh.ssh_vars.l,
                r=ssh.ssh_vars.r,
                i=ssh.ssh_vars.i,
                v=ssh.ssh_vars.v,
                debug=ssh.ssh_vars.debug,
                status=ssh.ssh_vars.status,
                destroy=ssh.ssh_vars.destroy)

    return 0


if __name__ == '__main__':
    main()
