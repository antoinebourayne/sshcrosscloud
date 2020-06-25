import logging
import os
from unittest import TestCase

import unittest.mock
from sshcrosscloud import utils
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud
import sshcrosscloud


class TestSSHCrossCloud(TestCase):
    command_arg = utils.default_args

    # AWS
    @unittest.mock.patch('os.system')
    def test_wait_until_initialization(self, os_system):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.ssh_fonctionnal_params = "a"
        ssh.ssh_params.pem_ssh = "b"
        ssh.ssh_params.instance_user = "c"
        ssh.ssh_params.public_ip = "d"
        ssh.ssh_params.verbose = True
        ssh.wait_until_initialization()
        os_system.assert_called_with("ssh a -v b c@d exit && echo $?")
        ssh.ssh_params.verbose = False
        ssh.wait_until_initialization()
        os_system.assert_called_with("ssh a b c@d exit && echo $?")

    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS, 'get_node')
    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS, 'spe_wait_until_running')
    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS, 'create_instance')
    def test_init_instance(self, spe_driver_create_instance, spe_driver_spe_wait_until_running, spe_driver_get_node):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.init_provider_specifics()
        ssh.init_instance(with_instance=True)
        spe_driver_get_node.assert_called()
        spe_driver_spe_wait_until_running.assert_called()

        ssh.init_instance(with_instance=False)
        spe_driver_get_node.assert_called()
        spe_driver_create_instance.assert_called()

    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.SSHCrossCloud, 'init_instance')
    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS, 'start_instance')
    def test_manage_instance(self, spe_start_instance, ssh_init_instance):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.init_provider_specifics()
        ssh.manage_instance()
        ssh.ssh_params.sshcrosscloud_instance_id = None
        ssh_init_instance.assert_called_with(with_instance=False)

        ssh.ssh_params.instance_state = "stopped"
        ssh.manage_instance()
        spe_start_instance.assert_called()
        ssh_init_instance.assert_called_with(with_instance=True)

    @unittest.mock.patch('os.system')
    def test_attach_to_instance(self, os_system):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.ssh_fonctionnal_params = "a"
        ssh.ssh_params.pem_ssh = "b"
        ssh.ssh_params.instance_user = "c"
        ssh.ssh_params.public_ip = "d"
        ssh.ssh_params.ssh_params = "e"
        ssh.ssh_params.verbose = True
        ssh.ssh_params.multiplex = False
        ssh.ssh_params.ssh_script = "f"
        ssh.attach_to_instance()
        os_system.assert_called_with("ssh a e -v b c@d f")

        ssh.ssh_params.verbose = False
        ssh.attach_to_instance()
        os_system.assert_called_with("ssh a e b c@d f")

        ssh.ssh_params.ssh_script = None
        ssh.attach_to_instance()
        os_system.assert_called_with("ssh a e b c@d ")

        ssh.ssh_params.multiplex = True
        ssh.ssh_params.instance_name = 'g'
        ssh.ssh_params.ssh_detach = True
        ssh.attach_to_instance()
        os_system.assert_called_with("ssh a e b c@d  -t 'tmux has-session -t g || tmux new-session -s g -d'")

        ssh.ssh_params.ssh_script = 'f'
        ssh.attach_to_instance()
        os_system.assert_called_with('ssh a e b c@d  -t \'tmux has-session -t g || tmux new-session -s g -d "f"\'')

        ssh.ssh_params.ssh_script = 'f'
        ssh.ssh_params.ssh_detach = False
        ssh.ssh_params.ssh_attach = True
        ssh.attach_to_instance()
        os_system.assert_called_with('ssh a e b c@d  -t \'tmux attach-session -t g || tmux new-session -s g "f"\'')

        ssh.ssh_params.ssh_script = None
        ssh.attach_to_instance()
        os_system.assert_called_with("ssh a e b c@d  -t 'tmux attach-session -t g || tmux new-session -s g'")

    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS, 'stop_instance')
    @unittest.mock.patch.object(sshcrosscloud.ssh_cross_cloud.libcloud_extended.SpecificAWS, 'terminate_instance')
    def test_finish_action(self, spe_terminate_instance, spe_stop_instance):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.init_provider_specifics()
        ssh.ssh_params.final_state = 'stop'
        ssh.finish_action()
        spe_stop_instance.assert_called()

        ssh.ssh_params.final_state = 'terminate'
        ssh.finish_action()
        spe_terminate_instance.assert_called()

    @unittest.mock.patch('os.system')
    def test_rsync_to_instance(self, os_system):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.ssh_fonctionnal_params = "a"
        ssh.ssh_params.pem_ssh = "b"
        ssh.ssh_params.instance_user = "c"
        ssh.ssh_params.public_ip = "d"
        ssh.ssh_params.rsync_directory = "e"
        ssh.ssh_params.verbose = False
        ssh.rsync_to_instance()
        os_system.assert_called_with("rsync -Pa -e 'ssh a b' --exclude-from='.rsyncignore' e/* c@d:/home/c")

        ssh.ssh_params.verbose = True
        ssh.rsync_to_instance()
        os_system.assert_called_with("rsync -Pav -e 'ssh a b' --exclude-from='.rsyncignore' e/* c@d:/home/c")

    @unittest.mock.patch('os.system')
    def test_rsync_back_to_local(self, os_system):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.pem_ssh = "b"
        ssh.ssh_params.instance_user = "c"
        ssh.ssh_params.public_ip = "d"
        ssh.ssh_params.rsync_directory = "e"
        ssh.ssh_params.verbose = False
        ssh.rsync_to_instance()
        os_system.assert_called_with("rsync -Pa -e 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o "
                                     "LogLevel=quiet b' --exclude-from='.rsyncignore' e/* c@d:/home/c")

        ssh.ssh_params.verbose = True
        ssh.rsync_to_instance()
        os_system.assert_called_with(
            "rsync -Pav -e 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o "
            "LogLevel=quiet b' --exclude-from='.rsyncignore' e/* c@d:/home/c")

    def test_check_parameters(self):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.leave = True
        ssh.ssh_params.stop = True
        self.assertRaises(Exception)

        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.provider = None
        self.assertRaises(Exception)

        ssh = SSHCrossCloud(**self.command_arg)
        ssh.ssh_params.detach = True
        ssh.ssh_params.attach = True
        self.assertRaises(Exception)

    def test_manage_commands(self):
        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.leave = True
        ssh.manage_commands()
        assert ssh_params.final_state == 'leave'

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.stop = True
        ssh.manage_commands()
        assert ssh_params.final_state == 'stop'

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.terminate = True
        ssh.manage_commands()
        assert ssh_params.final_state == 'terminate'

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.detach = True
        ssh.manage_commands()
        assert ssh_params.final_state == 'leave'
        assert ssh_params.ssh_detach is True
        assert ssh_params.multiplex is True

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.attach = True
        ssh.manage_commands()
        assert ssh_params.final_state == 'leave'
        assert ssh_params.ssh_attach is True
        assert ssh_params.multiplex is True
        assert ssh_params.no_rsync_begin is True
        assert ssh_params.no_rsync_end is True

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.finish = True
        ssh.manage_commands()
        assert ssh_params.no_rsync_begin is True

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.norsync = True
        ssh.manage_commands()
        assert ssh_params.no_rsync_begin is True
        assert ssh_params.no_rsync_end is True

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.provider = "test"
        ssh.manage_commands()
        assert ssh_params.provider == "test"

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.l = "L_param"
        ssh_params.ssh_params = "a"
        ssh.manage_commands()
        assert ssh_params.ssh_params == "a -L L_param"

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.r = "R_param"
        ssh_params.ssh_params = "a"
        ssh.manage_commands()
        assert ssh_params.ssh_params == "a -R R_param"

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.i = "i_param"
        ssh.manage_commands()
        assert ssh_params.pem_ssh == "-i i_param"

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.debug = True
        ssh.manage_commands()
        assert ssh_params.verbose is True

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.config = True
        ssh.manage_commands()
        assert ssh_params.config is True

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.status = True
        ssh.manage_commands()
        assert ssh_params.status_mode is True
        assert ssh_params.no_rsync_begin is True
        assert ssh_params.no_rsync_end is True
        assert ssh_params.no_attach is True
        assert ssh_params.no_wait_until_init is True

        ssh = SSHCrossCloud(**self.command_arg)
        ssh_params = ssh.ssh_params

        ssh_params.destroy = True
        ssh.manage_commands()
        assert ssh_params.no_rsync_begin is True
        assert ssh_params.no_rsync_end is True
        assert ssh_params.no_attach is True
        assert ssh_params.final_state == 'terminate'
