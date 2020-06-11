import sys

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
    print('-----SSH CROSS CLOUD-----')

    # Variable Initialization
    ssh_vars = utils.SSHVar(vars(parser.parse_args()))

    # SSH Object
    ssh = SSHCrossCloud(ssh_vars)

    # Manage credentials
    ssh.spe_driver.write_credentials(utils.get_ui_credentials(ssh))

    # Init libcloud driver, specific driver and get existing instance if it exists
    ssh.init_provider_specifics()

    # TODO: where to put this ?
    ssh.spe_driver.ssh_vars = ssh.ssh_vars
    ssh.spe_driver.driver = ssh.driver

    # Have a look at the existing instances
    ssh.spe_driver.display_instances()

    # Fetch existing instance or create one
    ssh.manage_instance()

    # Try to connect multiple times to the instance to check the connection
    ssh.wait_until_initialization()

    # Copy directory from local computer to instance
    ssh.rsync_to_instance()

    # SSH connection to instance
    ssh.attach_to_instance()

    # When done synchronize back to local directory
    ssh.rsync_back_to_local()

    # How to finish process
    ssh.finish_action()

    print('SSH CROSS CLOUD - END')

    return 0


if __name__ == '__main__':
    main()
