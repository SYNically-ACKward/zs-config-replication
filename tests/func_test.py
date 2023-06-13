import pytest
import tomli
from unittest.mock import MagicMock
import os
from src.zs_config_replication import (
    check_for_changes,
    apply_child_fw_ruleset,
)


@pytest.fixture
def config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src", "config.toml")
    # Create a fixture to load the configuration from the `config.toml` file
    with open(config_path, "rb") as cf:
        config = tomli.load(cf)
    return config


def test_config_file_exists(config):
    # Test that the `config.toml` file exists
    assert "PARENT" in config
    assert "SUB1" in config
    assert "SUB2" in config
