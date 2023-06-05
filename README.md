# Config Replication v3

Config Replication is a Python script designed to synchronize firewall and security configurations between a parent organization and its child tenants. It allows for the automatic replication of configuration changes from the parent organization to each child tenant, ensuring consistency across multiple environments.

## Installation

1. Clone the repository:

```shell
git clone https://github.com/SYNically-ACKward/zs-config-replication.git
```

2. Install the required dependencies:

```shell
pip install -r requirements.txt
```

## Usage

1. Update the `config.toml` file with the necessary configuration details for the parent organization and child tenants.

2. Run the script:

```shell
python zs_config_replication.py
```

The script will authenticate the parent organization, check for configuration changes, and apply those changes to the child tenants' configurations.

## Configuration

The `config.example` file should be changed to 'config.toml' and filled in with the configuration settings for the script. Ensure that you update the file with the appropriate values for your parent organization and child tenants.

## Contributing

Contributions to this project are welcome. If you have any suggestions, bug fixes, or feature enhancements, please submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Acknowledgments

- Thanks to the authors for developing and sharing the Config Replication v3 script.
- Thanks to OpenAI for providing assistance and generating the README using the AI language model.