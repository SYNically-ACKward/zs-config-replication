import pytest
import configparser
from unittest.mock import MagicMock
import sys
import os
# Append the parent directory of the current file to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../src")
from src.zs_config_replication import (
    authenticate_session,
    check_for_changes,
    apply_child_fw_ruleset,
)

@pytest.fixture
def config():
    # Create a fixture to load the configuration from the `config.toml` file
    config = configparser.ConfigParser()
    config.read("config.toml")
    return config

def test_config_file_exists(config):
    # Test that the `config.toml` file exists
    assert "PARENT" in config
    assert "SUB_TENANT_1" in config
    assert "SUB_TENANT_2" in config

def test_authentication():
    # Test authentication with the parent organization
    api_key = "your_api_key"
    username = "your_username"
    password = "your_password"
    baseUrl = "your_base_url"

    session = authenticate_session(api_key, username, password, baseUrl)
    assert session is not None

def test_check_for_changes(mocker, config):
    # Create a mocked session object
    session = MagicMock()

    # Set up the expected return value for session.get()
    expected_json = {
        "status": "COMPLETE",
        "changes": True
    }
    session.get.return_value.json.return_value = expected_json

    # Mock the requests.Session() to return the mocked session
    mocker.patch("zs_config_replication.requests.Session", return_value=session)

    baseUrl = "your_base_url"
    assert check_for_changes(session, baseUrl) is True
    session.get.assert_called_with(f"{baseUrl}auditlogEntryReport", headers=mocker.ANY)

def test_apply_child_fw_ruleset(mocker, config):
    # Create a mocked session object
    session = MagicMock()

    # Mock the requests.Session() to return the mocked session
    mocker.patch("zs_config_replication.requests.Session", return_value=session)

    baseUrl = "your_base_url"
    fw_ruleset = [
        # Define a mock firewall ruleset
        {"name": "Rule 1", "action": "Allow"},
        {"name": "Rule 2", "action": "Deny"},
    ]

    apply_child_fw_ruleset(session, baseUrl, fw_ruleset)

    # Assert that the firewall ruleset is correctly applied
    session.post.assert_called_with(
        f"{baseUrl}firewallFilteringRules",
        data='{"name": "Rule 1", "action": "Allow"}',
        headers={"content-type": "application/json", "cache-control": "no-cache"},
    )
    session.post.assert_called_with(
        f"{baseUrl}firewallFilteringRules",
        data='{"name": "Rule 2", "action": "Deny"}',
        headers={"content-type": "application/json", "cache-control": "no-cache"},
    )
