from zia_talker.zia_talker import ZiaTalker
import logging
import time
import csv
import io
import copy
import datetime
import tomli
import sys
from icecream import ic
from tqdm import tqdm  # Import the tqdm library for displaying progress bars


# Enable IC debugging
ic.enable()

# Load TOML config file
with open('config.toml', "rb") as cf:
    config = tomli.load(cf)


def check_for_changes():
    current_timestamp = datetime.datetime.now().timestamp() * 1000
    parent.add_auditlogEntryReport(startTime=(current_timestamp - (6 * 60 * 1000)),
                                   endTime=current_timestamp,
                                   actionTypes=["UPDATE", "CREATE"])
    while True:
        report_status = parent.list_auditlogEntryReport()
        if report_status['status'] == 'ERRORED':
            print("Error retrieving change report. Exiting Application.")
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
    configuration['url_bl'] = parent.list_security_blacklisted_urls()
    return configuration


def build_child_fw_ruleset(policy: dict, nwServcies: dict) -> list:
    parent_policy = copy.deepcopy(policy)
    new_ruleset = []
    for rule in parent_policy['fw']:  # Iterate through each rule in the parent policy
        if rule['name'] in [i['name'] for i in child.list_firewallFilteringRules()]:
            print(f"Rule {rule['name']} already exists at location {rule['order']}.")
            pass
        else:  # Otherwise, add the rule to the child policy
            del rule['id']
            if 'destIpCategories' in str(rule):
                del rule['destIpCategories']
            if 'resCategories' in str(rule):
                del rule['resCategories']
            if 'destCountries' in str(rule):
                del rule['destCountries']
            if 'labels' in str(rule):
                for rule_label in rule['labels']:
                    if rule_label['name'] != 'pscm-high' or 'pscm-low':
                        del rule['labels']
                    else:
                        for label in child_labels:
                            if label['name'] == rule_label['name']:
                                rule_label['id'] = label['id']
            if 'nwServices' in rule:
                for nwService in rule['nwServices']:
                    for service in nwServcies:
                        if service['name'] == nwService['name']:
                            nwService['id'] = service['id']
            print(f"New rule with name {rule['name']} will be created in position {rule['order']}.")
            new_ruleset.append(rule)
    return sorted(new_ruleset, key=lambda x: x['order'])  # Sort the new policy by rule order


def apply_child_fw_ruleset(fw_ruleset):
    for rule in fw_ruleset:
        response = child.add_firewallFilteringRules(**rule)
        time.sleep(1)
        ic(response.json())
        if 'code' in response.content.decode():
            print(f"Error with Rule Name: {rule['name']} for tenant {tenant}")
            print(f"Error: {response.json()['code']}")
            print(f"Error: {response.json()['message']}")
    child.activate_status()


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


if __name__ == "__main__":
    run_count = 1
    changes = False
    while True:
        parent = ZiaTalker(f"{config['PARENT']['cloudId']}")
        parent.authenticate(config['PARENT']['api_key'],
                            config['PARENT']['username'],
                            config['PARENT']['password'])
        changes = check_for_changes()
        parent_config = gather_parent_config()
        if changes or run_count == 0:
            if run_count == 0:
                print("This is the inital run. Proceeding with configuration sync...")
            else:
                print("Changes have been detected. Proceeding with configuration sync...")

            for tenant in [key for key in config.keys() if 'SUB' in key]:
                child = ZiaTalker(f"{config[f'{tenant}']['cloudId']}")
                child.authenticate(config[f'{tenant}']['api_key'],
                                   config[f'{tenant}']['username'],
                                   config[f'{tenant}']['password'])
                child_nw_services = child.list_networkServices()
                validate_tenant_labels()
                child_labels = child.list_rule_labels()
                child_fw_ruleset = build_child_fw_ruleset(parent_config, child_nw_services)
                apply_child_fw_ruleset(child_fw_ruleset)
                print(f"Configuration Sync Complete for tenant {tenant}.\n")
            print("Full Configuration Sync Complete.")
            run_count += 1
            hold_timer(300)

        else:
            if run_count > 0:
                run_count += 1
                print(f"No changes have been detected in the last 360 seconds. This is run number {run_count}.")
            hold_timer(300)
