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
import json
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

# Configure Logging
logging.basicConfig(filename=os.path.join(script_dir, f"logs/{time.time()}.log"), level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')




def check_for_changes(tenantId):
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

    if num_rows > 0:
        return True
    else:
        return False


def read_configuration(tenantId):
    configuration = {}
    tenant = ZiaTalker(config[f'{tenantId}']['cloudId'])
    tenant.authenticate(config[f'{tenantId}']['api_key'],
                        config[f'{tenantId}']['username'],
                        config[f'{tenantId}']['password'])
    configuration['FW Filtering'] = tenant.list_firewallFilteringRules()
    configuration['URL Blacklist'] = tenant.list_security_blacklisted_urls()
    return configuration

def write_config_to_db(tenantId, configuration):
    if run_count == 0:
        # Setup initial db for tenant
        dbcon = sqlite3.connect(f'db/{tenantId}.db')
        dbcon.execute('''CREATE TABLE Configuration (
        id TEXT PRIMARY KEY,
        tenantId TEXT,
        timestamp REAL,
        name TEXT,
        config TEXT
        )''')
    # Gather FW Config and Insert new row into table
    dbcon.execute(f'''INSERT INTO Configuration (id, tenantId,
                  timestamp, name, config)
                  VALUES (?, ?, ?, ?, ?)''',
                    (f"{run_count}-FW", f"{tenantId}",
                     time.time(), "FW Filtering",
                     json.dumps(configuration['FW Filtering'])))
    # Gather URL Blacklist and Insert new row into table
    dbcon.execute(f'''INSERT INTO Configuration (id, tenantId,
                  timestamp, name, config)
                  VALUES (?, ?, ?, ?, ?)''',
                    (f"{run_count}-URL", f"{tenantId}",
                     time.time(), "URL Blacklist",
                     json.dumps(configuration['URL Blacklist'])))
    dbcon.commit()


def read_config_from_db(tenantId, conf_type):
    if run_count == 0:
        values = (f"0-{conf_type}")
    else:
        values = (f"{(run_count) - 1}-{conf_type}")
    dbcon = sqlite3.connect(f'db/{tenantId}.db')
    c = dbcon.cursor()
    c.execute('''SELECT * FROM Configuration WHERE id=?''', values)
    configuration = c.fetchall()
    return configuration


if __name__ == "__main__":
    run_count = 0
    while True:
        if run_count == 0:
            logging.info(f"First run started at {time.time()}.")
            parent_configuration = read_configuration("PARENT")
            write_config_to_db("PARENT", parent_configuration)
            run_count += 1
            print(read_config_from_db("PARENT", "FW"))
        elif run_count > 0:
            exit()
