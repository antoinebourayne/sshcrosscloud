import logging
import os
from pathlib import Path
import boto3
import stat

logging.getLogger().setLevel(logging.INFO)


class Ec2config:
    def __init__(self, ex_ssh):
        self.ssh = ex_ssh
        self.driver = boto3.client('ec2', self.ssh.env['REGION'])

    def create_rsa_key_pair(self):
        logging.info("Creating key pair")

        if os.path.isfile(str(Path.home()) + "/.ssh" + self.ssh.env['USERNAME']):
            logging.info(
                "Creating key pair from existing key in " + str(Path.home()) + "/.ssh" + self.ssh.env['USERNAME'])
            self.driver.import_key_pair_from_file(self.ssh.env['USERNAME'],
                                                  str(Path.home()) + "/.ssh" + self.ssh.env['USERNAME'])
        else:
            keypair = self.driver.create_key_pair(KeyName=self.ssh.env['USERNAME'])
            rsa_key = keypair.get('KeyMaterial')

            with open(str(Path.home()) + "/.ssh/" + self.ssh.env['USERNAME'], 'w') as file:
                file.write(rsa_key)
            os.chmod(str(Path.home()) + "/.ssh/" + self.ssh.env['USERNAME'], stat.S_IRWXU)

        logging.info("Key pair created")
