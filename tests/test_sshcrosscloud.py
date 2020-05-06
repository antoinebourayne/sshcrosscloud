import os
from unittest import TestCase
from sshcrosscloud import SSHCrossCloud, create_instance, wait_until_initialization, \
    attach_to_instance, stop_instance, terminate_instance, display_instances
from os import environ


class Test(TestCase):
    def test_sshds_init_env(self):
        ssh = SSHCrossCloud()

        ssh.defaultdict['TESTDICT'] = 'ok'

        fake_dotenv = open("../.env", "a")
        fake_dotenv.write("\nTESTDOTENV=ok\n")
        fake_dotenv.close()

        environ['TESTENV'] = "ok"

        ssh.set_env()

        assert ssh.env['TESTDICT'] == "ok"
        assert ssh.env['TESTDOTENV'] == "ok"
        assert ssh.env['TESTENV'] == "ok"

        # erase testing data
        fin = open("../.env", "rt")
        data = fin.read()
        data = data.replace('\nTESTDOTENV=ok', '')
        fin.close()
        fin = open("../.env", "wt")
        fin.write(data)
        fin.close()
        del environ['TESTENV']

    def test_sshds_init_env_default_only(self):
        ssh = SSHCrossCloud()
        ssh.defaultdict = {'testdict': 'ok'}
        ssh.set_env()
        assert ssh.env['testdict'] == "ok"

    def test_sshds_init_env_dotenv_only(self):
        ssh = SSHCrossCloud()
        dotenv = open("../.env", "a")
        dotenv.write("TESTDOTENV=ok\n")
        dotenv.close()
        ssh.set_env()
        assert ssh.env['TESTDOTENV'] == "ok"

        # erase testing data
        fin = open("../.env", "rt")
        data = fin.read()
        data = data.replace('\nTESTDOTENV=ok', '')
        fin.close()
        fin = open("../.env", "wt")
        fin.write(data)
        fin.close()

    def test_sshds_init_env_environ_only(self):
        ssh = SSHCrossCloud()
        environ['TESTENV'] = "ok"
        ssh.set_env()
        assert ssh.env['TESTENV'] == "ok"
        del environ['TESTENV']

    def test_sshds_init_default_user_list(self):
        ssh = SSHCrossCloud()
        user_list = {
            'Amazon Linux': 'ec2-user',
            'ubuntu': 'ubuntu',
            'RHEL 6.[0-3]': 'root',
            'RHEL 6.[0-9]+': 'ec2-user',
            'Fedora': 'fedora',
            'Centos': 'centos',
            'SUSE': 'ec2-user',
            'BitNami': 'bitnami',
            'TurnKey': 'root',
            'NanoStack': 'ubuntu',
            'FreeBSD': 'ec2-user',
            'OmniOS': 'root',
        }
        assert ssh.default_user_list == user_list

    def test_display_instances(self):
        ssh = SSHCrossCloud()
        display_instances(ssh)

    def test_create_aws_instance(self):
        ssh = SSHCrossCloud()
        terminate_instance(ssh)
        assert create_instance(ssh) == 0

    def test_wait_until_initialization_no_instance(self):
        ssh = SSHCrossCloud()
        create_instance(ssh)
        assert wait_until_initialization(ssh) == 0

    def test_wait_until_initialization_with_instance(self):
        ssh = SSHCrossCloud()
        assert wait_until_initialization(ssh) == 0

    def test_attach_to_instance(self):
        ssh = SSHCrossCloud()
        attach_to_instance(ssh)

    def test_stop_instances(self):
        ssh = SSHCrossCloud()
        assert stop_instance(ssh) == 0

    def test_terminate_instances(self):
        os.environ['PROVIDER'] = 'AZURE'
        ssh = SSHCrossCloud()
        assert terminate_instance(ssh) == 0
