import logging
import os
from pathlib import Path
import boto3


class EC2Configuration():
    def __init__(self):
        ec2_cli = boto3.client('ec2')
        self.instances = ec2_cli.describe_instances()

        # TODO: s'occuper des credentials, les stocker ou il faut au démmarage
        # TODO: create key pair
        # TODO: create security group ici ?

    # Credentials
    # try:
    #     os.system(aws_login)
    # except:
    #     try:
    #         install_aws_cli = "pip3 install awscli --upgrade --user"
    #         os.system(install_aws_cli)
    #         os.system(aws_login)
    #     except:
    #         logging.warning("Error, cannot get the AWS CLI")
    #
    # # SSH Key-Pair
    # create_key_pair_command = "(cd " + str(Path.home()) + "/.ssh &&" \
    #                                                       " aws ec2 create-key-pair --key-name " + os.environ[
    #                               'USERNAME'] + \
    #                           " --output text > " + os.environ['USERNAME'] + ".pem &&" \
    #                                                                          " chmod 400 " + os.environ[
    #                               'USERNAME'] + ".pem)"
    # os.system(create_key_pair_command)

config = EC2Configuration()
print(config.instances)