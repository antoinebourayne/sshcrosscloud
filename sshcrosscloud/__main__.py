import logging
import os
import sys

import coloredlogs

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

    # Verbose
    if command_args['v']:
        logging.getLogger().setLevel(logging.INFO)
        coloredlogs.install(level='INFO')

    ssh = SSHCrossCloud(**command_args)
    ssh.execute()
    # ssh.execute('ls')

    return 0


if __name__ == '__main__':
    main()
