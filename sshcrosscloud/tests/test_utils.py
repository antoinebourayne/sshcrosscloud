import sys
from unittest import TestCase

from sshcrosscloud.utils import SSHVar


class Test(TestCase):
    def test_get_string_from_file(self):
        self.fail()

    def test_get_public_key(self):
        self.fail()

    def test_get_ui_credentials(self):
        self.fail()


class TestSSHVar(TestCase):
    default_args = {'sshscript': None,
                    'leave': False,
                    'stop': False,
                    'terminate': False,
                    'finish': False,
                    'detach': False,
                    'attach': False,
                    'verbose': False,
                    'status': False,
                    'destroy': False,
                    'norsync': False,
                    'debug': False,
                    'config': False,
                    'v': False,
                    'provider': None,
                    'L': None,
                    'R': None,
                    'i': None}

    def test__init_commands(self):
        args = self.default_args
        args['leave'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.final_state == 'leave'

        args = self.default_args
        args['stop'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.final_state == 'stop'

        args = self.default_args
        args['terminate'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.final_state == 'terminate'

        args = self.default_args
        args['detach'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.final_state == 'leave'
        assert ssh_var.ssh_detach == True
        assert ssh_var.multiplex == True

        args = self.default_args
        args['attach'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.final_state == 'leave'
        assert ssh_var.ssh_attach == True
        assert ssh_var.multiplex == True
        assert ssh_var.no_rsync_begin == True
        assert ssh_var.no_rsync_end == True

        args = self.default_args
        args['finish'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.no_rsync_begin == True

        args = self.default_args
        args['verbose'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.rsync_verbose == True

        args = self.default_args
        args['norsync'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.no_rsync_begin == True
        assert ssh_var.no_rsync_end == True

        args = self.default_args
        args['provider'] = "test"
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.provider == "test"

        args = self.default_args
        args['L'] = "L_param"
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.ssh_params == " -L L_param"

        args = self.default_args
        args['R'] = "R_param"
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.ssh_params == " -L L_param -R R_param"

        args = self.default_args
        args['i'] = "i_param"
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.pem_ssh == "-i i_param"

        args = self.default_args
        args['debug'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.debug == True

        args = self.default_args
        args['config'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.config == True

        args = self.default_args
        args['status'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.status_mode == True
        assert ssh_var.no_rsync_begin == True
        assert ssh_var.no_rsync_end == True
        assert ssh_var.no_attach == True
        assert ssh_var.no_wait_until_init == True

        args = self.default_args
        args['destroy'] = True
        ssh_var = SSHVar(self.default_args)
        assert ssh_var.no_rsync_begin == True
        assert ssh_var.no_rsync_end == True
        assert ssh_var.no_attach == True
        assert ssh_var.final_state == 'terminate'
