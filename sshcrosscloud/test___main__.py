from unittest import TestCase

from sshcrosscloud.__main__ import arg_leave, arg_stop, arg_terminate, arg_detach, arg_attach, arg_finish, arg_config, \
    arg_destroy, arg_provider, arg_debug, arg_L, arg_R, arg_i, arg_no_rsync
from sshcrosscloud.ssh_cross_cloud import SSHCrossCloud


class Test(TestCase):
    def test_arg_leave(self):
        pre_env = {}
        arg_leave(pre_env)
        assert pre_env['FINAL_STATE'] == 'leave'

    def test_arg_stop(self):
        pre_env = {'SSH_DETACH': 'y'}
        arg_stop(pre_env)
        assert pre_env.get('FINAL_STATE') is None
        pre_env = {}
        arg_stop(pre_env)
        assert pre_env.get('FINAL_STATE') == 'stop'

    def test_arg_terminate(self):
        pre_env = {'SSH_DETACH': 'y'}
        arg_terminate(pre_env)
        assert pre_env.get('FINAL_STATE') is None
        pre_env = {}
        arg_terminate(pre_env)
        assert pre_env.get('FINAL_STATE') == 'terminate'

    def test_arg_detach(self):
        pre_env = {}
        arg_detach(pre_env)
        assert pre_env['FINAL_STATE'] == 'leave'
        assert pre_env['SSH_DETACH'] == 'y'
        assert pre_env['MULTIPLEX'] == 'y'

    def test_arg_attach(self):
        pre_env = {}
        arg_attach(pre_env)
        assert pre_env["MULTIPLEX"] == "y"
        assert pre_env["SSH_ATTACH"] == "y"
        assert pre_env["FINAL_STATE"] == "leave"
        assert pre_env["NO_RSYNC_BEGIN"] == "y"
        assert pre_env["NO_RSYNC_END"] == "y"

    def test_arg_finish(self):
        pre_env = {}
        arg_finish(pre_env)
        assert pre_env['NO_RSYNC_BEGIN'] == 'y'

    def test_arg_config(self):
        pre_env = {}
        arg_config(pre_env)
        assert pre_env['CONFIG'] == 'y'

    def test_arg_destroy(self):
        pre_env = {}
        arg_destroy(pre_env)
        assert pre_env["NO_RSYNC_BEGIN"] == "y"
        assert pre_env["NO_RSYNC_END"] == "y"
        assert pre_env["NO_ATTACH"] == "y"
        assert pre_env["FINAL_STATE"] == "terminate"

    def test_arg_provider(self):
        pre_env = {}
        arg_provider(pre_env, 'test')
        assert pre_env['PROVIDER'] == 'TEST'

    def test_arg_debug(self):
        pre_env = {}
        arg_debug(pre_env)
        assert pre_env['DEBUG'] == 'y'

    def test_arg_l(self):
        pre_env = {}
        arg_L(pre_env, 'test')
        assert pre_env['SSH_PARAMS'] == " -L test"
        pre_env = {'SSH_PARAMS': 'y'}
        arg_L(pre_env, 'test')
        assert pre_env['SSH_PARAMS'] == "y -L test"

    def test_arg_r(self):
        pre_env = {}
        arg_R(pre_env, 'test')
        assert pre_env['SSH_PARAMS'] == " -R test"
        pre_env = {'SSH_PARAMS': 'y'}
        arg_R(pre_env, 'test')
        assert pre_env['SSH_PARAMS'] == "y -R test"

    def test_arg_i(self):
        pre_env = {}
        arg_i(pre_env, 'test')
        assert pre_env['PEM_SSH'] == "-i test"

    def test_arg_no_rsync(self):
        pre_env = {}
        arg_no_rsync(pre_env)
        assert pre_env['NO_RSYNC_BEGIN'] == 'y'
        assert pre_env['NO_RSYNC_END'] == 'y'

    def test_arg_verbose(self):
        pre_env = {}
        arg_no_rsync(pre_env)
        assert pre_env['RSYNC_VERBOSE'] == 'y'

    def test_wait_until_initialization(self):
        pass

    def test_wait_for_public_ip(self):
        self.fail()

    def test_attach_to_instance(self):
        self.fail()

    def test_finish_action(self):
        self.fail()

    def test_stop_instance(self):
        self.fail()

    def test_start_instance(self):
        self.fail()

    def test_terminate_instance(self):
        self.fail()

    def test_rsync_to_instance(self):
        self.fail()

    def test_rsync_back_to_local(self):
        self.fail()
