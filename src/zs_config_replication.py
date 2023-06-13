from zia_talker.zia_talker import ZiaTalker
import logging
import time
import csv
import io
import copy
import datetime
import tomli
import sys
import os
import sqlite3
from sqlite3 import Error
from icecream import ic
from tqdm import tqdm  # Import the tqdm library for displaying progress bars


# Enable IC debugging
ic.disable()

# Load TOML config file
script_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(script_dir, "config.toml")

with open(config_path, "rb") as cf:
    config = tomli.load(cf)


def check_for_changes():
    current_timestamp = datetime.datetime.now().timestamp() * 1000
    parent.add_auditlogEntryReport(startTime=(current_timestamp - (6 * 60 * 1000)),
                                   endTime=current_timestamp,
                                   actionTypes=["UPDATE", "CREATE"])
    while True:
        report_status = parent.list_auditlogEntryReport()
        if report_status['status'] == 'ERRORED':
            logging.error("Error retrieving change report. Exiting Application.")
            sys.exit("Gathering Change Report Failed.")
        elif report_status['status'] == 'COMPLETE':
            break
        time.sleep(5)

    file_content = parent.download_auditlogEntryReport()
    data_string = file_content.content.decode('utf-8')
    reader = csv.reader(io.StringIO(data_string))

    for i in range(5):
        next(reader)
    num_rows = sum(1 for row in reader) - 1

    if num_rows > 0:
        return True
    else:
        return False


def gather_parent_config():
    configuration = {}
    configuration['fw'] = parent.list_firewallFilteringRules()
    for rule in configuration['fw']:
        parent_db.execute(
            '''INSERT INTO FirewallRules (id, name, action, destCountries, destIpCategories, labels, nwServices, rank, description, enableFullLogging, `order`, state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                rule['id'],
                rule['name'],
                rule['action'],
                str(rule['destCountries']),
                str(rule.get('destIpCategories')),
                str(rule.get('labels')),
                str(rule.get('nwServices')),
                rule.get('rank'),
                rule.get('description'),
                rule['enableFullLogging'],
                rule['order'],
                rule['state']
            )
        )
    configuration['url_bl'] = parent.list_security_blacklisted_urls()
    parent_db.commit()
    return configuration


def build_child_fw_ruleset(policy: dict) -> list:
    parent_policy = copy.deepcopy(policy)
    new_ruleset = []
    return sorted(new_ruleset, key=lambda x: x['order'])  # Sort the new policy by rule order


def apply_child_fw_ruleset(fw_ruleset):
    for rule in fw_ruleset:
        response = child.add_firewallFilteringRules(**rule)
        time.sleep(1)
        ic(response.json())
        if 'code' in response.content.decode():
            logging.error(f"Error with Rule Name: {rule['name']} for tenant {tenant}")
            logging.error(f"Error: {response.json()['code']}")
            logging.error(f"Error: {response.json()['message']}")
    child.activate_status()


def apply_child_url_bl(url_blacklist):
    child.add_security_blacklistUrls(url_blacklist)


def validate_tenant_labels():
    current_labels = child.list_rule_labels()
    if 'pscm-high' and 'pscm-low' in [label['name'] for label in current_labels]:  # Check if the required labels exist
        pass
    else:  # If the required labels do not exist, create them
        label_data = [{  # Define the label data for the new labels
            'name': 'pscm-high',
            'description': 'pscm-high'
        }, {
            'name': 'pscm-low',
            'description': 'pscm-low'
        }]
        for label in label_data:
            response = child.add_rule_label(label)
            ic(response)
            time.sleep(1)


def hold_timer(duration: int):
    for i in tqdm(range(duration, 0, -1), desc="Next Run In", unit="sec", bar_format="{desc}: {remaining} {bar}"):
        time.sleep(1)


def create_db_connection(path):
    connection = None
    try:
        connection = sqlite3.connect(path)
        logging.info("Connection to SQLite DB Successful.")
    except Error as e:
        logging.error(f"The error '{e}' occurred.")
    
    return connection


if __name__ == "__main__":
    run_count = 0
    changes = False
    parent_db = create_db_connection('db/parent.db')
    parent_db.execute('''CREATE TABLE FirewallRules (
    id INTEGER PRIMARY KEY,
    name TEXT,
    action TEXT,
    destCountries TEXT,
    destIpCategories TEXT,
    labels TEXT,
    nwServices TEXT,
    rank INTEGER,
    description TEXT,
    enableFullLogging INTEGER,
    `order` INTEGER,
    state TEXT
    )''')
    while True:
        parent = ZiaTalker(f"{config['PARENT']['cloudId']}")
        parent.authenticate(config['PARENT']['api_key'],
                            config['PARENT']['username'],
                            config['PARENT']['password'])
        changes = check_for_changes()
        parent_config = gather_parent_config()
        if changes or run_count == 0:
            if run_count == 0:
                logging.info("This is the inital run. Proceeding with configuration sync.")
            else:
                logging.info("Changes have been detected. Proceeding with configuration sync...")

            for tenant in [key for key in config.keys() if 'SUB' in key]:
                child = ZiaTalker(f"{config[f'{tenant}']['cloudId']}")

                child.authenticate(config[f'{tenant}']['api_key'],
                                   config[f'{tenant}']['username'],
                                   config[f'{tenant}']['password'])

                validate_tenant_labels()

                child_fw_ruleset = build_child_fw_ruleset(parent_config)

                # apply_child_fw_ruleset(child_fw_ruleset)

                # apply_child_url_bl(parent_config['url_bl'])

                logging.info(f"Configuration Sync Complete for tenant {tenant}.\n")

            logging.info("Full Configuration Sync Complete.")
            run_count += 1
            hold_timer(300)

        else:
            if run_count > 0:
                run_count += 1
                logging.info(f"No changes have been detected in the last 360 seconds. This is run number {run_count}.")
            hold_timer(300)
