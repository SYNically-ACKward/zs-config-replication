import requests  # Import the requests library for making HTTP requests
import json  # Import the json library for handling JSON data
import time  # Import the time library for handling timestamps
import csv  # Import the csv library for reading and writing CSV files
import io  # Import the io library for handling file I/O
import copy  # Import the copy library for making copies of objects
import datetime  # Import the datetime library for handling dates and times
import tomli  # Import the tomli library for handling TOML configuration files
import sys  # Import the sys library for interacting with the Python interpreter
from tqdm import tqdm  # Import the tqdm library for displaying progress bars
from icecream import ic  # Import the icecream library for debugging

# Enable IC debugging
ic.disable()

# Load TOML config file
with open('config.toml', "rb") as cf:  # Open the TOML configuration file in binary mode
    config = tomli.load(cf)  # Load the configuration data into a dictionary

headers = {
    'content-type': "application/json",  # Set the content type to JSON
    'cache-control': "no-cache"  # Disable caching
}


def obfuscateApiKey(apikey):
    seed = apikey
    now = int(time.time() * 1000)  # Get the current timestamp in milliseconds
    n = str(now)[-6:]  # Extract the last six digits of the timestamp
    r = str(int(n) >> 1).zfill(6)  # Shift the digits one bit to the right and pad with zeroes
    key = ""
    for digit in n:
        key += seed[int(digit)]  # Append the character from the seed at the position of the digit
    for digit in r:
        key += seed[int(digit) + 2]  # Append the character from the seed at the position of the digit plus 2
    return now, key  # Return the timestamp and the obfuscated key


def authenticate_session(apikey: str, username: str,
                         password: str, baseUrl: str):
    now, key = obfuscateApiKey(apikey)  # Obfuscate the API key
    auth_data = {
        "apiKey": key,
        "username": username,
        "password": password,
        "timestamp": now  # Use the obfuscated API key and timestamp for authentication
    }
    session = requests.Session()  # Create a new session object
    response = session.post(f"{baseUrl}authenticatedSession",  # Authenticate the session with the API
                            data=json.dumps(auth_data),
                            headers=headers).cookies['JSESSIONID']
    session.cookies.set("JSESSIONID", response)  # Set the session ID cookie
    return session  # Return the authenticated session


def check_for_changes(session, baseUrl: str):
    current_timestamp = datetime.datetime.now().timestamp() * 1000  # Get the current timestamp in milliseconds
    reportData = json.dumps({
        "startTime": current_timestamp - (6 * 60 * 1000),  # Set the start time to 6 minutes ago
        "endTime": current_timestamp,  # Set the end time to the current time
        "page": 1,
        "pageSize": 100,
        "actionTypes": [
            "UPDATE"
        ]
    })
    session.post(f'{baseUrl}auditlogEntryReport',  # Generate a report of recent changes in the firewall policy
                 headers=headers, data=reportData)

    while True:
        report_status = session.get(f"{baseUrl}auditlogEntryReport",
                                    headers=headers).json()
        ic(report_status)  # Print the status of the change report
        if report_status['status'] == 'ERRORED':  # If there was an error, exit the application
            print("Error retrieving change report. Exiting Application.")
            sys.exit("Gathering Change Report Failed.")
        elif report_status['status'] == 'COMPLETE':  # If the report is complete, continue
            break
        time.sleep(5)

    file_content = session.get(f"{baseUrl}auditlogEntryReport/download",  # Download the change report as a CSV file
                               headers=headers)
    data_string = file_content.content.decode('utf-8')  # Convert the file content to a string
    reader = csv.reader(io.StringIO(data_string))  # Create a CSV reader object from the string

    for i in range(5):  # Skip the first 5 rows of the CSV file (header rows)
        next(reader)
    num_rows = sum(1 for row in reader) - 1  # Count the number of rows in the CSV file (excluding the header row)

    if num_rows > 0:  # If there are changes in the report, return True
        return True
    else:  # Otherwise, return False
        return False


def get_fw_policy(session, baseUrl: str) -> list:
    FW_Filtering = session.get(f"{baseUrl}firewallFilteringRules",  # Get the firewall policy from the API
                               headers=headers).json()
    FW_Filtering_no_default = [
        x for x in FW_Filtering if (
            'Default Firewall Filtering Rule' not in x.get('name')  # Exclude the default rule from the policy
        )
    ]
    return sorted(FW_Filtering_no_default, key=lambda x: x['order'])  # Sort the policy by rule order


def get_url_blacklist(session, baseUrl: str) -> dict:
    return session.get(f"{baseUrl}security/advanced",  # Get the URL blacklist from the API
                       headers=headers).json()


def get_tenant_nwServices(session, baseUrl: str) -> dict:
    return session.get(f"{baseUrl}networkServices",  # Get the network services from the API
                       headers=headers).json()


def get_tenant_locations(session, baseUrl: str) -> list:
    return session.get(f"{baseUrl}locations",  # Get the locations from the API
                       headers=headers).json


def get_tenant_labels(session, baseUrl: str) -> list:
    return session.get(f"{baseUrl}ruleLabels",  # Get the rule labels from the API
                       headers=headers).json()


def get_child_fw_ruleset(session, baseUrl: str) -> list:
    FW_Filtering = session.get(f"{baseUrl}firewallFilteringRules",  # Get the firewall policy from the API
                               headers=headers).json()
    FW_Filtering_no_default = [
        x for x in FW_Filtering if (
            'Default Firewall Filtering Rule' not in x.get('name')  # Exclude the default rule from the policy
        )
    ]
    return sorted(FW_Filtering_no_default, key=lambda x: x['order'])  # Sort the policy by rule order


def validate_child_labels(session, baseUrl: str) -> list:
    current_labels = session.get(f"{baseUrl}ruleLabels",  # Get the rule labels from the API
                                 headers=headers).json()
    if 'pscm-high' and 'pscm-low' in [label['name'] for label in current_labels]:  # Check if the required labels exist
        pass
    else:  # If the required labels do not exist, create them
        create_tenant_labels(session, baseUrl)


def create_tenant_labels(session, baseUrl: str):
    label_data = [{  # Define the label data for the new labels
        'name': 'pscm-high',
        'description': 'pscm-high'
    }, {
        'name': 'pscm-low',
        'description': 'pscm-low'
    }]
    for label in label_data:  # Create each label
        session.post(f"{baseUrl}ruleLabels",  # Post the label data to the API
                     data=json.dumps(label), headers=headers)
        time.sleep(1)
    session.post(f"{baseUrl}status/activate",  # Activate the labels
                 data="", headers=headers).json()


def build_child_fw_ruleset(session, parent_policy: list, nwServcies: list,  # Build the child firewall policy
                           labels: list, current_policy: list) -> list:
    parent_policy = copy.deepcopy(parent_policy)  # Create a deep copy of the parent policy
    new_ruleset = []
    for rule in parent_policy:  # Iterate through each rule in the parent policy
        if rule['name'] in [i['name'] for i in current_policy]:  # If the rule already exists in the child policy, skip it
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
                        for label in labels:
                            if label['name'] == rule_label['name']:
                                rule_label['id'] = label['id']
            if 'nwServices' in rule:
                for nwService in rule['nwServices']:
                    for service in nwServcies:
                        if service['name'] == nwService['name']:
                            nwService['id'] = service['id']
            new_ruleset.append(rule)
    return sorted(new_ruleset, key=lambda x: x['order'])  # Sort the new policy by rule order


def apply_child_fw_ruleset(session, baseUrl: str, fw_ruleset):  # Apply the child firewall policy to the API
    for rule in fw_ruleset:
        ic(rule)
        firewallFilteringRulesPost = session.post(  # Post the rule data to the API
            f"{baseUrl}firewallFilteringRules",
            data=json.dumps(rule), headers=headers)
        time.sleep(1)
        ic(firewallFilteringRulesPost.json())
        if 'code' in firewallFilteringRulesPost.content.decode():  # If there was an error, print it
            print(f"Error with Rule Name: {rule['name']} for tenant {tenant}")
            print(f"Error: {firewallFilteringRulesPost.json()['code']}")
            print(f"Error: {firewallFilteringRulesPost.json()['message']}")
    session.post(f"{baseUrl}status/activate",  # Activate the new policy
                 data="", headers=headers).json()


def apply_child_url_blacklist(session, baseUrl: str, url_blacklist: list):
    return session.post(f"{baseUrl}security/advanced/blacklistUrls", headers=headers,
                        data=json.dumps(url_blacklist))


def hold_timer(duration: int):
    for i in tqdm(range(duration), desc="Next Run In", unit="sec"):  # Display a progress bar for the timer
        time.sleep(1)


if __name__ == "__main__":
    run_count = 0  # Initialize the run count
    changes = False  # Initialize the changes variable
    while True:  # Loop indefinitely
        parentSession = authenticate_session(config['PARENT']['api_key'],  # Authenticate the parent session
                                             config['PARENT']['username'],
                                             config['PARENT']['password'],
                                             config['PARENT']['baseUrl'])
        changes = check_for_changes(parentSession, config['PARENT']['baseUrl'])  # Check for changes in the parent policy
        if changes or run_count == 0:  # If there are changes or this is the first run
            if run_count == 0:  # If this is the first run, print a message
                print("This is the inital run. Proceeding with configuration sync...")
            else:  # Otherwise, print a message indicating changes were detected
                print("Changes have been detected. Proceeding with configuration sync...")
            parentSession = authenticate_session(config['PARENT']['api_key'],  # Re-authenticate the parent session
                                                 config['PARENT']['username'],
                                                 config['PARENT']['password'],
                                                 config['PARENT']['baseUrl'])
            parent_fw_policy = get_fw_policy(parentSession,  # Get the parent firewall policy
                                             config['PARENT']['baseUrl'])
            parent_url_bl_policy = get_url_blacklist(parentSession,  # Get the parent URL blacklist policy
                                                     config['PARENT']['baseUrl'])

            for tenant in [key for key in config.keys() if 'SUB' in key]:  # Iterate through each child tenant
                child_session = authenticate_session(config[f'{tenant}']['api_key'],  # Authenticate the child session
                                                     config[f'{tenant}']['username'],
                                                     config[f'{tenant}']['password'],
                                                     config[f'{tenant}']['baseUrl']
                                                     )

                validate_child_labels(child_session, config[f'{tenant}']['baseUrl'])  # Validate the child labels

                child_fw_ruleset = build_child_fw_ruleset(child_session,  # Build the child firewall policy
                                                          parent_fw_policy,
                                                          get_tenant_nwServices(child_session,
                                                                                config[f'{tenant}']['baseUrl']),
                                                          get_tenant_labels(child_session,
                                                                            config[f'{tenant}']['baseUrl']),
                                                          get_child_fw_ruleset(child_session,
                                                                               config[f'{tenant}']['baseUrl']))

                apply_child_fw_ruleset(child_session,  # Apply the child firewall policy
                                       config[f'{tenant}']['baseUrl'],
                                       child_fw_ruleset)

                apply_child_url_blacklist(child_session,  # Apply the child URL blacklist policy
                                          config[f'{tenant}']['baseUrl'],
                                          parent_url_bl_policy)

                print(f"Configuration Sync Complete for tenant {tenant}.\n")  # Print a message indicating the configuration sync is complete
            print("Full Configuration Sync Complete.")  # Print a message indicating the full configuration sync is complete
            run_count += 1  # Increment the run count
            hold_timer(300)  # Wait 5 minutes before checking for changes again

        else:  # If there are no changes
            if run_count > 0:  # If this is not the first run, print a message indicating no changes were detected
                run_count += 1
                print(f"No changes have been detected. This is run number {run_count}.")
            hold_timer(300)  # Wait 5 minutes before checking for changes
