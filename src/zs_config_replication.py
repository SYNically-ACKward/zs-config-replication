import csv
import datetime
import io
import json
import logging
import os
import shutil
import sqlite3
import sys
import time
from sqlite3 import Error

import tomli
from icecream import ic
from tqdm import tqdm 

from zia_talker.zia_talker import ZiaTalker



# Enable IC debugging
ic.enable()

# Load TOML config file
script_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(script_dir, "config.toml")

with open(config_path, "rb") as cf:
    config = tomli.load(cf)

# Configure Logging
logging.basicConfig(filename=os.path.join(script_dir,
                                          f"logs/{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.log"),
                                          level=logging.DEBUG,
                                          format='%(asctime)s - %(levelname)s - %(message)s')


def check_for_changes(tenantId: str):
    tenant = ZiaTalker(config[f'{tenantId}']['cloudId'])
    tenant.authenticate(config[f'{tenantId}']['api_key'],
                        config[f'{tenantId}']['username'],
                        config[f'{tenantId}']['password'])
    current_timestamp = datetime.datetime.now().timestamp() * 1000
    tenant.add_auditlogEntryReport(startTime=(current_timestamp - (6 * 60 * 1000)),
                                   endTime=current_timestamp,
                                   actionTypes=["UPDATE", "CREATE"])
    while True:
        report_status = tenant.list_auditlogEntryReport()
        if report_status['status'] == 'ERRORED':
            logging.error("Error retrieving change report. Exiting Application.")
            sys.exit("Gathering Change Report Failed.")
        elif report_status['status'] == 'COMPLETE':
            break
        time.sleep(5)

    file_content = tenant.download_auditlogEntryReport()
    data_string = file_content.content.decode('utf-8')
    reader = csv.reader(io.StringIO(data_string))

    for i in range(5):
        next(reader)
    num_rows = sum(1 for row in reader) - 1

    return num_rows > 0


def read_configuration(tenantId: str):
    configuration = {}
    tenant = ZiaTalker(config[f'{tenantId}']['cloudId'])
    tenant.authenticate(config[f'{tenantId}']['api_key'],
                        config[f'{tenantId}']['username'],
                        config[f'{tenantId}']['password'])
    configuration['FW Filtering'] = tenant.list_firewallFilteringRules()
    configuration['URL Blacklist'] = tenant.list_security_blacklisted_urls()
    return configuration

def write_config_to_db(tenantId: str, configuration: dict):
    dbcon = sqlite3.connect(f'db/{tenantId}.db')
    if run_count == 0:
        # Setup initial db for tenant
        for attempt in range(5):
            try:
                dbcon = sqlite3.connect(f'db/{tenantId}.db')
                dbcon.execute('''CREATE TABLE Configuration (
                id TEXT PRIMARY KEY,
                tenantId TEXT,
                timestamp REAL,
                name TEXT,
                config TEXT
                )''')
                break
            except sqlite3.OperationalError as e:
                if 'table Configuration already exists' in str(e):
                    logging.error("The database already exists. Archiving old database and retrying.")
                    logging.error(e)
                    move_db_to_archive(f'{tenantId}.db')
                    time.sleep(1)
                else:
                    logging.error(e)
                    raise

    # Gather FW Config and Insert new row into table
    insert_query = f'''INSERT INTO Configuration (id, tenantId,
                  timestamp, name, config)
                  VALUES (?, ?, ?, ?, ?)'''
    dbcon.execute(insert_query,
                    (f"{run_count}-FW", f"{tenantId}",
                     time.time(), "FW Filtering",
                     json.dumps(configuration['FW Filtering'])))
    # Gather URL Blacklist and Insert new row into table
    dbcon.execute(insert_query,
                    (f"{run_count}-URL", f"{tenantId}",
                     time.time(), "URL Blacklist",
                     json.dumps(configuration['URL Blacklist'])))
    dbcon.commit()


def read_config_from_db(tenantId: str, conf_type: str, run_count: int) -> list:
    values = (f"{run_count}-{conf_type}",)
    dbcon = sqlite3.connect(f'db/{tenantId}.db')
    c = dbcon.cursor()
    c.execute('''SELECT config FROM Configuration WHERE id=?''', values)
    configuration = c.fetchall()
    return configuration

import json

def id_changed_rules(old_parent_policy: list, new_parent_policy: list):
    if old_parent_policy and isinstance(old_parent_policy[0], tuple):
        old_parent_policy = json.loads(old_parent_policy[0][0])

    if new_parent_policy and isinstance(new_parent_policy[0], tuple):
        new_parent_policy = json.loads(new_parent_policy[0][0])

    new_parent_policy_dict = {rule['id']: rule for rule in new_parent_policy}

    changed_rules = []

    for rule in old_parent_policy:
        if rule['id'] in new_parent_policy_dict and not deep_equal(rule, new_parent_policy_dict[rule['id']]):
            changed_rules.append(rule['id'])

    return changed_rules

def build_child_fw_rules():
    changes = id_changed_rules(read_config_from_db("PARENT", "FW", run_count),
                               read_config_from_db("PARENT", "FW", (run_count-1)))


def write_to_children(parent_configuration):
    for tenant in [key for key in config.keys() if 'SUB' in key]:
        child_configuration = {}
        child = ZiaTalker(f"{config[f'{tenant}']['cloudId']}")
        child.authenticate(config[f'{tenant}']['api_key'],
                            config[f'{tenant}']['username'],
                            config[f'{tenant}']['password'])
        child_configuration['FW Filtering'] = build_child_fw_rules(parent_configuration['FW Filtering'])
        # Write to DB at the end before return
        write_config_to_db(tenant, child_configuration)
        
def deep_equal(obj1, obj2):
    if type(obj1) != type(obj2):
        return False

    if isinstance(obj1, dict):
        if len(obj1) != len(obj2):
            return False
        for key in obj1:
            if key not in obj2:
                return False
            if not deep_equal(obj1[key], obj2[key]):
                logging.info(f'Dictionary keys not equal:\n'
                             f'Object 1: {obj1[key]}\n'
                             f'Object 2: {obj2[key]}')
                return False
        return True

    if isinstance(obj1, list):
        if len(obj1) != len(obj2):
            return False
        for i in range(len(obj1)):
            if not deep_equal(obj1[i], obj2[i]):
                logging.info(f'List items not equal:\n'
                             f'Object 1: {obj1[i]}\n'
                             f'Object 2: {obj2[i]}')
                return False
        return True

    # For simple data types (not list or dict)
    if obj1 != obj2:
        logging.info(f'Items not equal:\n'
                     f'Object 1: {obj1}\n'
                     f'Object 2: {obj2}')
        return False
    else:
        return True


def move_db_to_archive(filename):
    archive_directory = "archive"
    if not os.path.exists(f"db/{archive_directory}"):
        os.makedirs(f"db/{archive_directory}")
    new_path = os.path.join(f"db/{archive_directory}", f"{filename}-{datetime.datetime.now()}")
    shutil.move(f"db/{filename}", new_path)
    logging.info(f"Database file was archived to {archive_directory}/{filename}.")


if __name__ == "__main__":
    run_count = 0
    while True:
        if run_count == 0:
            logging.debug(f"First run started.")
            parent_configuration = read_configuration("PARENT")
            write_config_to_db("PARENT", parent_configuration)
            # write_to_children(parent_configuration)
            run_count += 1
        elif run_count > 0:
            if check_for_changes("PARENT"):
                parent_configuration = read_configuration("PARENT")
                write_config_to_db("PARENT", parent_configuration)
                ic(id_changed_rules(read_config_from_db("PARENT", "FW", run_count), read_config_from_db("PARENT", "FW", (run_count-1))))
                # ic(deep_equal(read_config_from_db("PARENT", "FW", run_count), read_config_from_db("PARENT", "FW", (run_count-1))))
                # Insert write policies to child tenant - If clause needed for if to update previusly created rules or not
                # How to avoid rewriting entire ruleset each time a new rule is created
                # write_to_children(parent_configuration)
            else:
                logging.debug(f"No changes detected for run count {run_count}. Sleeping for five minutes.")
                time.sleep(30)
            run_count += 1
