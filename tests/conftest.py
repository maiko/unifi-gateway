from configparser import ConfigParser

import pytest


@pytest.fixture
def gateway_config():
    config = ConfigParser()
    config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "ports": "[]", "is_adopted": "true"},
        "provisioned": {},
    })
    return config
