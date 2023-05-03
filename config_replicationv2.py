import requests
import json
import time
import tomli
from icecream import ic

# Enable IC debugging
ic.enable()

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


def build_child_fw_ruleset(session, baseUrl: str, policy: list) -> list:
    pass


def apply_child_fw_ruleset(session, baseUrl: str, fw_ruleset):
    pass


if __name__ == "__main__":
    parentSession = authenticate_session(config['PARENT']['api_key'],
                                         config['PARENT']['username'],
                                         config['PARENT']['password'],
                                         config['PARENT']['baseUrl'])

    parent_fw_policy = get_fw_policy(parentSession,
                                     config['PARENT']['baseUrl'])

    for tenant in [key for key in config.keys() if 'SUB' in key]:
        child_session = authenticate_session(config[f'{tenant}']['api_key'],
                                             config[f'{tenant}']['username'],
                                             config[f'{tenant}']['password'],
                                             config[f'{tenant}']['baseUrl']
                                             )

        child_fw_ruleset = build_child_fw_ruleset(child_session,
                                                  config[f'{tenant}']['baseUrl'],
                                                  parent_fw_policy)

        apply_child_fw_ruleset(child_session,
                               config[f'{tenant}']['baseUrl'],
                               child_fw_ruleset)
        time.sleep(1)
