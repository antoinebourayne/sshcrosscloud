import logging
from pathlib import Path


def get_string_from_file(filepath):
    with open(filepath, 'r') as userdatafile:
        return userdatafile.read()

def get_public_key(name: str) -> str:
    try:
        with open(str(Path.home()) + ".ssh/" + name + ".pub", 'r') as file:
            rsa_pub = file.read()
        return rsa_pub
    except:
        logging.info("No key at :" + str(Path.home()) + ".ssh/" + name + ".pub")