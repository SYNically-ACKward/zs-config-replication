import requests
import json
import time
import tomli


# Load TOML config file
with open('config.toml', "rb") as cf:
    config = tomli.load(cf)


data = {
    'client_id': f"{config['OAUTH']['client_id']}",
    'client_secret': f"{config['OAUTH']['client_secret']}",
    'grant_type': 'client_credentials',
    'scope': f"{config['OAUTH']['scope']}",
}

response = requests.post(f"{config['OAUTH']['token_url']}",
                         data=data, verify=False).json()

temp_header = {
    "Authorization": "Bearer " + str(response['access_token'])
}

print('''Below is the header used to authenticate
       to all managed tenants and main tenant''')

print(json.dumps(temp_header))

# insert base cloud to insert into URL for API calls to Zscaler REST API
zscaler_cloud = 'zscalerbeta.net'

# mini zscm in zdx cloud - zscm-lite specific for zdx components
# feature enablements and control are in micro ZSCM
# whenever they roll out it is not dependent on ZIA rollout

# one execution per 5 min per tenant

# api key, for more information on obtaining the key link is below:
# https://help.zscaler.com/zia/getting-started-zia-api#RetrieveAPIKey
parent_api_key = f"{config['PARENT']['api_key']}"
tenant_1_zscaler_api_key = f"{config['SUB1']['api_key']}"
# tenant_2_zscaler_api_key = f"{config['SUB2']['api_key']}"

# admin portal usernames for authentication
parent_tenant_username = f"{config['PARENT']['username']}"
child_tenant_1_username = f"{config['SUB1']['username']}"
# child_tenant_2_username = f"{config['SUB2']['username']}"

# passwords for admins user used for api authentication
parent_tenant_password = f"{config['PARENT']['password']}"
child_tenant_1_password = f"{config['SUB1']['password']}"
# child_tenant_2_password = f"{config['SUB2']['password']}"

# defining variables in order to authenticate to Zscaler API
# The base URL for Beta API is zsapi.zscalerbeta.net/api/v1
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

    # print("Timestamp:", now, "\tKey", key)
    return [now, key]


def get_policy_from_tenants(apikey, username, password):
    # executing function to return obfuscated key and timestamp
    key_and_timestamp = obfuscateApiKey(apikey)
    # crafting header for performing API calls
    header = {
        'content-type': "application/json",
        'cache-control': "no-cache"
        }
    # zscaler API Auth Url to fetch JSESSIONID
    zscaler_api_authentication_url = f'https://admin.{zscaler_cloud}/api/v1/authenticatedSession'
    # username, password, api key and timestamp
    # are used to authenticate to Zscaler API
    data_for_api_call = {
                        "apiKey": key_and_timestamp[1],
                        "username": username,
                        "password": password,
                        "timestamp": key_and_timestamp[0]
    }
    # using the .Session method to grab the Cookie to authenticate future requests
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
        FW_Filtering = session.get(f"{zscaler_base_url}firewallFilteringRules", headers=header, verify=False).json()
        #print(f'firewallFilteringRules: {session.get(f"{zscaler_base_url}firewallFilteringRules", headers=header).json()}')
        FW_Filtering_no_default_rules = [x for x in FW_Filtering if 'Default Firewall Filtering Rule' not in str(x['name']) and \
            'Zscaler Proxy Traffic' not in str(x['name']) and 'Office 365 One Click Rule' not in str(x['name']) and \
            'Recommended Firewall Rule' not in str(x['name']) and 'HTTP' not in str(x['name'])]
        #print(FW_Filtering_no_default_rules)
        time.sleep(1)
        # performing get to blacklist URLs 
        BL_URLs = session.get(f"{zscaler_base_url}security/advanced", headers=header, verify=False).json()
        #print(f'Blacklist URLs: {session.get(f"{zscaler_base_url}security/advanced", headers=header).json()}')

        time.sleep(1)

        return(FW_Filtering_no_default_rules, BL_URLs)


#get_policy_from_tenants(tenant_2_zscaler_api_key, child_tenant_2_username, child_tenant_2_password)
#get_policy_from_tenants(tenant_3_zscaler_api_key, child_tenant_3_username, child_tenant_3_password)
#get_policy_from_tenants(tenant_4_zscaler_api_key, child_tenant_4_username, child_tenant_4_password)
#get_policy_from_tenants(tenant_5_zscaler_api_key, child_tenant_5_username, child_tenant_5_password)

def update_policy(apikey, username, password, current_master_policy):

    # executing function to return obfuscated key and timestamp
    key_and_timestamp = obfuscateApiKey(apikey)

    # crafting header for performing API calls
    header = {
        'content-type': "application/json",
        'cache-control': "no-cache"
        }

    # zscaler API Auth Url to fetch JSESSIONID
    zscaler_api_authentication_url = f'https://admin.{zscaler_cloud}/api/v1/authenticatedSession'

    # username, password, api key and timestamp are used to authenticate to Zscaler API
    data_for_api_call = {
    "apiKey": key_and_timestamp[1],
    "username": username, 
    "password": password,
    "timestamp": key_and_timestamp[0]
    }

    # using the .Session method to grab the Cookie to authenticate future requests
    with requests.Session() as session:

        # performing api call to authenticate to zia api and obtain cookie info
        response = session.post(zscaler_api_authentication_url, data=json.dumps(data_for_api_call), headers = header, verify=False).cookies['JSESSIONID']

        # setting the cookies for future request 
        session.cookies.set("JSESSIONID", response)

        ####### now that we have a set cookie for the session we can begin all the policy config APIs
        # performiing set of get API calls for policies of newly provisioned tenant to ensure there are no pre-existing values
        # also to avoid any api limitations, a 1 second sleep interval was inserted between API calls
        payload = json.dumps(current_master_policy[0])
        new_payload = current_master_policy[0][0]
        #print(new_payload)
        try:
            del new_payload['id']
        except:
            print("no action needed")
        if 'destIpCategories' in str(new_payload):
            del new_payload['destIpCategories']
        if 'resCategories' in str(new_payload):
            del new_payload['resCategories']
        if 'destCountries' in str(new_payload):
            del new_payload['destCountries']

        new_payload.update({"description":"test"}) 
        #print(json.dumps([new_payload]))


        network_services_response = session.get(f"{zscaler_base_url}networkServices", headers=header, data={}, verify=False).json()

        #print(network_services_response)

        
        for rule in [new_payload]:
            print(json.dumps(rule))


            #print(rule['nwServices'][0])


            for service in network_services_response:

                if 'nwServices' in str(rule):

                    if str(rule['nwServices'][0]['name']) in str(service['name']):
                        print(service)
                        new_net_service_id = service['id']

                        rule_data = {
                        "accessControl":rule['accessControl'],
                        "enableFullLogging":rule['enableFullLogging'],
                        "name":rule['name'],
                        "order":rule['order'],
                        "rank":rule['rank'],
                        "action":rule['action'],
                        "state":rule['state'],
                        "nwServices":[{"id":service['id'],"name":rule['nwServices'][0]['name'],"isNameL10nTag":rule['nwServices'][0]['isNameL10nTag']}],
                        "predefined":rule['predefined'],
                        "defaultRule":rule['defaultRule'],
                        "description":rule['description']
                        }

                        #del rule['nwServices']
                        #print(rule)
                    
        
                    firewallFilteringRulesPost = session.post(f"{zscaler_base_url}firewallFilteringRules", data=json.dumps(rule_data), headers=header).json()
                    time.sleep(1)
                    print(firewallFilteringRulesPost)   
        
        # activating change 
        session.post(f"{zscaler_base_url}status/activate", data="", headers=header).json()

        
        time.sleep(1)

        # performing post to update blacklist URLs for child tenants
        payload = json.dumps(current_master_policy[1]).replace("'",'"')
        time.sleep(1)

        #update_bl_url = session.post(f"{zscaler_base_url}security/advanced/blacklistUrls?action=ADD_TO_LIST", headers=header, data=payload)
        update_bl_url = session.put(f"{zscaler_base_url}security/advanced", headers=header, data=payload)

        print(update_bl_url)
        # activating change 
        session.post(f"{zscaler_base_url}status/activate", data="", headers=header).json()
        
        return























'''
2 tenants
lakeland health (own tenant on zs2)
spectrum health (bought lakeland in 2018) (had tenant on zs3)
in lakeland renewal we bundled for 65k users
the licenses got assigned to the legacy tenant




The QA team was able to validate the fix in the Alpha Cloud

Additionally we were able to work with the Cloud Ops team and get this scheduled

Unfortunately we were only able to get this into the Saturday Maintenance window at 5am pacific

The schedule is made weeks in advance and we were able to get this expedited to Saturday

Is there something we can do in the meantime? Give you a beta tenant with the login that has a replication of customer policies?







threat labz
why BT Zscaler refresher
why RSMs asking
Eagle I 
managed service









'''










while True:

    # executing function to fetch all current policies from tenants
    current_master_policy = get_policy_from_tenants(master_zscaler_api_key, master_tenant_username, master_tenant_password)
    print(current_master_policy)
    time.sleep(1)

    update_policy(tenant_1_zscaler_api_key, child_tenant_1_username, child_tenant_1_password, current_master_policy)


    time.sleep(5)


# special settings and add on

