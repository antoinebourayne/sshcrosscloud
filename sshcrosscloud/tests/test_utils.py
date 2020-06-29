import sys
from unittest import TestCase

import dotenv

from sshcrosscloud import utils
from sshcrosscloud.utils import SSHParams
import unittest.mock


class Test(TestCase):
    @unittest.mock.patch('os.path.isfile')
    @unittest.mock.patch('builtins.open', new_callable=unittest.mock.mock_open, read_data='test')
    def test_get_string_from_file(self, m_open, m_isfile):
        m_isfile.return_value = True
        assert utils.get_string_from_file('foo') == 'test'

        m_isfile.return_value = False
        assert utils.get_string_from_file('foo') is None

    @unittest.mock.patch('os.path.isfile')
    @unittest.mock.patch('builtins.open', new_callable=unittest.mock.mock_open, read_data='pub_key')
    def test_get_public_key(self, m_open, m_isfile):
        m_isfile.return_value = True
        assert utils.get_public_key('foo') == 'pub_key'
        m_isfile.assert_called_with('foo.pub')
        m_open.assert_called_with('foo.pub', 'r')

        m_isfile.return_value = False
        with self.assertRaises(Exception):
            utils.get_public_key('foo')

    @unittest.mock.patch('builtins.input')
    def test_get_ui_confirmation(self, m_input):
        m_input.return_value = 'y'
        assert utils.get_ui_confirmation('foo') is True

        m_input.return_value = 'n'
        assert utils.get_ui_confirmation('foo') is False


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
                    'config': False,
                    'v': False,
                    'provider': None,
                    'L': None,
                    'R': None,
                    'i': None}

    @unittest.mock.patch.dict('os.environ', {'FOO': 'bar'})
    @unittest.mock.patch('dotenv.dotenv_values')
    @unittest.mock.patch('dotenv.find_dotenv')
    def test_update_custom_values(self, find_dotenv, dotenv_values):
        # FIXME: patch for find_dotenv and dotenv_values doesn't work
        ssh_params = SSHParams(**self.default_args)
        ssh_params.foo = None
        ssh_params.update_custom_values(replace_dotenv=False, replace_environ=True)
        assert ssh_params.foo == 'bar'


