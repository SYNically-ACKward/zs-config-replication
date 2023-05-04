from zia_talker.zia_talker import ZiaTalker
import requests
import json
import time
import csv
import io
import copy
import datetime
import tomli
import sys
from icecream import ic

# Enable IC debugging
ic.disable()

# Load TOML config file
with open('config.toml', "rb") as cf:
    config = tomli.load(cf)

headers = {
            'content-type': "application/json",
            'cache-control': "no-cache"
            }


def obfuscateApiKey(apikey):
    seed = apikey
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""
    for digit in n:
        key += seed[int(digit)]
    for digit in r:
        key += seed[int(digit) + 2]
    return now, key


def authenticate_session(apikey: str, username: str,
                         password: str, baseUrl: str):
    now, key = obfuscateApiKey(apikey)
    auth_data = {
        "apiKey": key,
        "username": username,
        "password": password,
        "timestamp": now
    }
    session = requests.Session()
    response = session.post(f"{baseUrl}authenticatedSession",
                            data=json.dumps(auth_data),
                            headers=headers).cookies['JSESSIONID']
    session.cookies.set("JSESSIONID", response)
    return session


def check_for_changes(session, baseUrl: str):
    current_timestamp = datetime.datetime.now().timestamp() * 1000
    reportData = json.dumps({
                  "startTime": current_timestamp - (6 * 60 * 1000),
                  "endTime": current_timestamp,
                  "page": 1,
                  "pageSize": 100,
                  "actionTypes": [
                      "UPDATE"
                  ]
                  })
    session.post(f'{baseUrl}auditlogEntryReport',
                 headers=headers, data=reportData)

    while True:
        report_status = session.get(f"{baseUrl}auditlogEntryReport",
                                    headers=headers).json()
        ic(report_status)
        if report_status['status'] == 'ERRORED':
            print("Error retrieving change report. Exiting Application.")
            sys.exit("Gathering Change Report Failed.")
        elif report_status['status'] == 'COMPLETE':
            break
        time.sleep(5)

    file_content = session.get(f"{baseUrl}auditlogEntryReport/download",
                               headers=headers)
    data_string = file_content.content.decode('utf-8')
    reader = csv.reader(io.StringIO(data_string))

    for i in range(5):
        next(reader)
    num_rows = sum(1 for row in reader) - 1

    if num_rows > 0:
        return True
    else:
        return False


def get_fw_policy(session, baseUrl: str) -> list:
    FW_Filtering = session.get(f"{baseUrl}firewallFilteringRules",
                               headers=headers).json()
    FW_Filtering_no_default_rules = [
        x for x in FW_Filtering if (
            'Default Firewall Filtering Rule' not in x.get('name') and
            'Zscaler Proxy Traffic' not in x.get('name') and
            'Office 365 One Click Rule' not in x.get('name') and
            'Recommended Firewall Rule' not in x.get('name') and
            'HTTP' not in x.get('name')
        )
    ]

    return FW_Filtering_no_default_rules


def get_url_blacklist(session, baseUrl: str) -> dict:
    return session.get(f"{baseUrl}security/advanced",
                       headers=headers).json()


def get_tenant_nwServices(session, baseUrl: str) -> dict:
    return session.get(f"{baseUrl}networkServices",
                       headers=headers).json()


def build_child_fw_ruleset(session, baseUrl: str, policy: list, nwServcies: dict) -> list:
    current_policy = copy.deepcopy(policy)
    new_ruleset = []
    for rule in current_policy:
        del rule['id']
        if 'destIpCategories' in str(rule):
            del rule['destIpCategories']

        if 'resCategories' in str(rule):
            del rule['resCategories']

        if 'destCountries' in str(rule):
            del rule['destCountries']

        if 'nwServices' in rule:
            for nwService in rule['nwServices']:
                for service in nwServcies:
                    if service['name'] == nwService['name']:
                        nwService['id'] = service['id']
        new_ruleset.append(rule)
    ic(new_ruleset)
    ic(tenant)
    return new_ruleset


def apply_child_fw_ruleset(session, baseUrl: str, fw_ruleset):
    for rule in fw_ruleset:
        ic(rule)
        firewallFilteringRulesPost = session.post(
            f"{baseUrl}firewallFilteringRules",
            data=json.dumps(rule), headers=headers)
        time.sleep(1)
        ic(firewallFilteringRulesPost.json())
        if 'code' in firewallFilteringRulesPost.content.decode():
            print(f"Error with Rule Name: {rule['name']} for tenant {tenant}")
            print(f"Error: {firewallFilteringRulesPost.json()['code']}")
            print(f"Error: {firewallFilteringRulesPost.json()['message']}")
    session.post(f"{baseUrl}status/activate",
                 data="", headers=headers).json()


if __name__ == "__main__":
    run_count = 0
    changes = False
    while True:
        parentSession = authenticate_session(config['PARENT']['api_key'],
                                             config['PARENT']['username'],
                                             config['PARENT']['password'],
                                             config['PARENT']['baseUrl'])
        changes = check_for_changes(parentSession, config['PARENT']['baseUrl'])
        if changes or run_count == 0:
            if run_count == 0:
                print("This is the inital run. Proceeding with configuration sync...")
            else:
                print("Changes have been detected. Proceeding with configuration sync...")
            parentSession = authenticate_session(config['PARENT']['api_key'],
                                                 config['PARENT']['username'],
                                                 config['PARENT']['password'],
                                                 config['PARENT']['baseUrl'])
            parent_fw_policy = get_fw_policy(parentSession,
                                             config['PARENT']['baseUrl'])
            parent_url_bl_policy = get_url_blacklist(parentSession,
                                                     config['PARENT']['baseUrl'])

            for tenant in [key for key in config.keys() if 'SUB' in key]:
                child_session = authenticate_session(config[f'{tenant}']['api_key'],
                                                     config[f'{tenant}']['username'],
                                                     config[f'{tenant}']['password'],
                                                     config[f'{tenant}']['baseUrl']
                                                     )

                child_fw_ruleset = build_child_fw_ruleset(child_session,
                                                          config[f'{tenant}']['baseUrl'],
                                                          parent_fw_policy,
                                                          get_tenant_nwServices(child_session,
                                                                                config[f'{tenant}']['baseUrl']))

                apply_child_fw_ruleset(child_session,
                                       config[f'{tenant}']['baseUrl'],
                                       child_fw_ruleset)
                print(f"Configuration Sync Complete for tenant {tenant}.")
            print("Full Configuration Sync Complete.")
            run_count += 1
            time.sleep(300)
        else:
            if run_count > 0:
                run_count += 1
                print(f"No changes have been detected. This is run number {run_count}.")

            time.sleep(300)

    # TESTING BLOCK
    # parentSession = authenticate_session(config['PARENT']['api_key'],
    #                                      config['PARENT']['username'],
    #                                      config['PARENT']['password'],
    #                                      config['PARENT']['baseUrl'])
    # changes = check_for_changes(parentSession, config['PARENT']['baseUrl'])
    # ic(changes)
    # parent_fw_policy = get_fw_policy(parentSession,
    #                                     config['PARENT']['baseUrl'])
    # for tenant in [key for key in config.keys() if 'SUB' in key]:
    #     child_session = authenticate_session(config[f'{tenant}']['api_key'],
    #                                             config[f'{tenant}']['username'],
    #                                             config[f'{tenant}']['password'],
    #                                             config[f'{tenant}']['baseUrl']
    #                                             )

    #     child_fw_ruleset = build_child_fw_ruleset(child_session,
    #                                                 config[f'{tenant}']['baseUrl'],
    #                                                 parent_fw_policy,
    #                                                 get_tenant_nwServices(child_session,
    #                                                                     config[f'{tenant}']['baseUrl']))
    #     print(child_fw_ruleset)
