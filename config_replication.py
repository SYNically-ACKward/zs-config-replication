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

zscaler_cloud = 'zscalerbeta.net'
zscaler_base_url = f'https://zsapi.{zscaler_cloud}/api/v1/'


# creating function to obfuscate the API key with a timestamp
def obfuscateApiKey(apikey):
    seed = apikey
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""
    for i in range(0, len(str(n)), 1):
        key += seed[int(str(n)[i])]
    for j in range(0, len(str(r)), 1):
        key += seed[int(str(r)[j])+2]

    return now, key


def get_policy(apikey, username, password):
    # executing function to return obfuscated key and timestamp
    now, key = obfuscateApiKey(apikey)
    # crafting header for performing API calls
    header = {
        'content-type': "application/json",
        'cache-control': "no-cache"
        }
    # zscaler API Auth Url to fetch JSESSIONID
    zscaler_api_authentication_url = f'{zscaler_base_url}authenticatedSession'
    # username, password, api key and timestamp
    # are used to authenticate to Zscaler API
    data_for_api_call = {
                        "apiKey": key,
                        "username": username,
                        "password": password,
                        "timestamp": now
                        }
    # using the .Session method to grab the
    # Cookie to authenticate future requests
    with requests.Session() as session:
        # performing api call to authenticate to zia api and obtain cookie info
        response = session.post(zscaler_api_authentication_url,
                                data=json.dumps(data_for_api_call),
                                headers=header,
                                verify=False).cookies['JSESSIONID']
        # setting the cookies for future request
        session.cookies.set("JSESSIONID", response)
        # now that we have a set cookie for the session
        # we can begin all the policy config APIs
        # performiing set of get API calls for policies of
        # newly provisioned tenant to ensure there are no pre-existing values
        # also to avoid any api limitations, a 1 second sleep
        # interval was inserted between API calls
        # performing GET to firewallFilteringRules endpoint and printing result
        FW_Filtering = session.get(f"{zscaler_base_url}firewallFilteringRules",
                                   headers=header, verify=False).json()
        FW_Filtering_no_default_rules = [
            x for x in FW_Filtering if (
                'Default Firewall Filtering Rule' not in x.get('name') and
                'Zscaler Proxy Traffic' not in x.get('name') and
                'Office 365 One Click Rule' not in x.get('name') and
                'Recommended Firewall Rule' not in x.get('name') and
                'HTTP' not in x.get('name')
            )
        ]
        time.sleep(1)
        # performing get to blacklist URLs
        BL_URLs = session.get(f"{zscaler_base_url}security/advanced",
                              headers=header, verify=False).json()
        time.sleep(1)

        return FW_Filtering_no_default_rules, BL_URLs


def update_policy(apikey, username, password, current_master_policy):

    # executing function to return obfuscated key and timestamp
    now, key = obfuscateApiKey(apikey)

    # crafting header for performing API calls
    header = {
        'content-type': "application/json",
        'cache-control': "no-cache"
        }

    # zscaler API Auth Url to fetch JSESSIONID
    zscaler_api_authentication_url = f'{zscaler_base_url}authenticatedSession'

    data_for_api_call = {
                        "apiKey": key,
                        "username": username,
                        "password": password,
                        "timestamp": now
    }

    with requests.Session() as session:

        response = session.post(zscaler_api_authentication_url,
                                data=json.dumps(data_for_api_call),
                                headers=header,
                                verify=False).cookies['JSESSIONID']

        session.cookies.set("JSESSIONID", response)

        network_services_response = session.get(
            f"{zscaler_base_url}networkServices",
            headers=header, verify=False).json()
        new_ruleset = []
        for rule in current_master_policy[0]:
            del rule['id']

            if 'destIpCategories' in str(rule):
                del rule['destIpCategories']

            if 'resCategories' in str(rule):
                del rule['resCategories']

            if 'destCountries' in str(rule):
                del rule['destCountries']

            if 'nwServices' in rule:
                for nwService in rule['nwServices']:
                    for service in network_services_response:
                        if service['name'] == nwService['name']:
                            nwService['id'] = service['id']

            new_ruleset.append(rule)

        for rule in new_ruleset:
            firewallFilteringRulesPost = session.post(
                f"{zscaler_base_url}firewallFilteringRules",
                data=json.dumps(rule), headers=header)
            if 'code' in firewallFilteringRulesPost.content.decode():
                print(f"Error with Rule Name: {rule['name']}")
                print(f"Error: {firewallFilteringRulesPost.json()['code']}")
                print(f"Error: {firewallFilteringRulesPost.json()['message']}")
            time.sleep(1)

        # activating change
        session.post(f"{zscaler_base_url}status/activate",
                     data="", headers=header).json()

        time.sleep(1)

        # # performing post to update blacklist URLs for child tenants
        # payload = json.dumps(current_master_policy[1]).replace("'", '"')
        # time.sleep(1)

        # update_bl_url = session.put(f"{zscaler_base_url}security/advanced",
        #                             headers=header, data=payload)

        # print(update_bl_url)
        # # activating change
        # session.post(f"{zscaler_base_url}status/activate", data="",
        #              headers=header).json()


if __name__ == '__main__':
    while True:
        current_master_policy = get_policy(config['PARENT']['api_key'],
                                           config['PARENT']['username'],
                                           config['PARENT']['password'])
        for tenant in [key for key in config.keys() if 'SUB' in key]:
            time.sleep(1)
            zscaler_base_url = f"https://zsapi.{config[f'{tenant}']['cloud_id']}/api/v1/" # noqa
            update_policy(config[f'{tenant}']['api_key'],
                          config[f'{tenant}']['username'],
                          config[f'{tenant}']['password'],
                          current_master_policy)

        time.sleep(300)
