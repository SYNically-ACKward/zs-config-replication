# zs-config-replication

# Configuration Synchronization Tool

This is a Python script that synchronizes firewall and security configurations between a parent organization and its child tenants. It does this by checking for changes in the parent organization's configuration, and applying those changes to each child tenant's configuration.

## Getting Started

These instructions will help you get the project up and running on your local machine for development and testing purposes.

### Prerequisites

To run this script, you will need:

- Python 3.x
- Requests library (can be installed via `pip`)
- TOML library (can be installed via `pip`)
- tqdm library (can be installed via `pip`)
- icecream library (can be installed via `pip`)

### Installing

To install the required libraries, simply run:

```
pip install requests
pip install toml
pip install tqdm
pip install icecream
```

## Running the script

To run the script, first make sure you have updated the `config.toml` file with the appropriate values for your parent organization and child tenants.

Then, simply run:

```
python main.py
```

This will start the script and begin synchronizing configurations.

## Contributing

Contributions to this project are welcome! If you have any suggestions or find any bugs, please submit a pull request or create an issue.

## Authors

- Ryan Ulrick (mailto:rulrick@zscaler.com)


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

- Thanks to OpenAI for providing the language model used to generate this README!