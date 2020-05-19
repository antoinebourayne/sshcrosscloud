from libcloud.compute.types import Provider


_DRIVERS = {
    Provider.EC2:
        'EC2ConfigDriver',
}


def get_config_driver(provider):
    if provider in _DRIVERS:
        driver_name = _DRIVERS[provider]
        return 0

    raise AttributeError('Provider %s does not exist' % (provider))


cls = get_config_driver(Provider.EC2)
