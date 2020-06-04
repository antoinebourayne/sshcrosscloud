from unittest import TestCase


class TestProviderSpecific(TestCase):
    def test_create_local_rsa_key_pair(self):
        self.fail()


class TestSpecificAWS(TestCase):
    def test_create_instance(self):
        self.fail()

    def test__init_rsa_key_pair(self):
        self.fail()

    def test__init_size(self):
        self.fail()

    def test__init_image(self):
        self.fail()

    def test__init_security_group(self):
        self.fail()


class TestSpecificAzure(TestCase):
    def test_create_instance(self):
        self.fail()

    def test__init_rsa_key_pair(self):
        self.fail()

    def test__init_size(self):
        self.fail()

    def test__init_image(self):
        self.fail()

    def test__init_location(self):
        self.fail()

    def test__init_resource_group(self):
        self.fail()

    def test__init_auth(self):
        self.fail()

    def test__init_virtual_network(self):
        self.fail()

    def test__init_security_group(self):
        self.fail()

    def test__init_public_ip(self):
        self.fail()

    def test__init_network_interface(self):
        self.fail()


class TestSpecificGPC(TestCase):
    def test_create_instance(self):
        self.fail()

    def test__init_rsa_key_pair(self):
        self.fail()

    def test__init_size(self):
        self.fail()

    def test__init_image(self):
        self.fail()

    def test__init_metadata(self):
        self.fail()
