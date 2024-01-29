from laceworksdk import LaceworkClient
import json
from datetime import datetime, timedelta, timezone
import argparse


# Use lacework SDK to authenticate API session
def get_lw_client(api_key, api_secret, account, subaccount=None):
    return LaceworkClient(api_key=api_key, api_secret=api_secret, account=account, subaccount=subaccount)


# Vuln data is returnes paginated. This function extracts all pages of the result
def handle_pages(generator):
    data = []
    for page in generator:
        data += page['data']
    return data


# Transform datetime object to string format required by API calls
def datetime_to_str(adate):
    """

    :type adate: datetime
    """
    return adate.strftime("%Y-%m-%dT%H:%M:%S%z")


# Vuln search API returns all packages, this parses out only ones with discovered vulns
def filter_not_vuln_packages(vuln_list):
    filtered_vuln_list = []
    for vuln in vuln_list:
        try:
            # If an entry in the data has a vulnId, add it to the fitlered list
            if (vuln['vulnId']):
                filtered_vuln_list.append(vuln)
        except KeyError:
            continue
    return filtered_vuln_list


# Finds all packages with the same VulnID and returns a dict with vulnId as the key and a list of affected
# packages as the value
def group_by_vulnid(vuln_list):
    vulns_by_id = {}
    for vuln in vuln_list:
        if vuln['vulnId'] not in vulns_by_id.keys():
            vulns_by_id[vuln['vulnId']] = []
        vulns_by_id[vuln['vulnId']].append(vuln)

    return vulns_by_id


# --------Parse script cli parameters------- #
parser = argparse.ArgumentParser(description='Command line parameter parsing with defaults')
parser.add_argument('-i', '--instanceid', type=str, required=True, help='InstanceID of the host to search')
parser.add_argument('-c', '--credentials', type=str, required=True,
                    help='Path to Lacework Administrator credential file')
parser.add_argument('-v', '--vulnid', type=str, help='Specific Vulnerability ID to fine')
parser.add_argument('-s', '--subaccount', type=str, help='Limit to specific subaccount')
parser.add_argument('-o', '--outputlocation', type=str, default='.', help='Location to place output files')
args = parser.parse_args()
machineId = args.instanceid
vulnId = args.vulnid
outputlocation = args.outputlocation.rstrip('/')
cred_file = args.credentials
if args.subaccount is None:
    subaccounts = []
else:
    subaccounts = [args.subaccount]
# ------- end parameter parsing ------- #

# Get credentials from passed credentials file
with open(cred_file, 'r') as file:
    # Load JSON data
    creds = json.load(file)

    # Extract data and store in variables
    api_key = creds['keyId']
    api_secret = creds['secret']
    account = creds['account']

# If subaccount not specified on cli, list all subaccounts via API
if not subaccounts:
    lw_client = get_lw_client(api_key, api_secret, account)
    userProfile = lw_client.user_profile.get()
    for lwaccount in userProfile['data'][0]['accounts']:
        subaccounts.append(lwaccount['accountName'].lower())

# Set time frame to last 1 day
current_time = datetime.now(timezone.utc)
start_time = current_time - timedelta(days=1)
end_time = current_time

# Begin search logic, looping through subaccounts if 1 not specified on command line
for subaccount in subaccounts:
    # get api session
    lw_client = get_lw_client(api_key, api_secret, account, subaccount)

    # search vuln data over lsat day, filter by InstanceId
    vuln_search_generator = lw_client.vulnerabilities.hosts.search(json={
        "timeFilter": {
            "startTime": datetime_to_str(start_time),
            "endTime": datetime_to_str(end_time)
        },
        "filters": [{"field": "machineTags.InstanceId", "expression": "eq", "value": machineId}],
        "returns": ["props", "severity", "status", "vulnId", "evalCtx", "fixInfo", "featureKey", "machineTags"]
    })

    # SDK returns an object to handle data pagination. Call function to pull all pages
    package_list = handle_pages(vuln_search_generator)

    # Remove packages with no vulns from data
    vulns_by_package = filter_not_vuln_packages(package_list)

    # Alternate view - group affected packages in a dict with vulnId as the key
    vulns_by_id = group_by_vulnid(vulns_by_package)

    # If a vulnId was specified on command line, determine if it's in the list
    vuln_found = False
    found_vuln = None
    if vulnId is not None:
        if vulnId in vulns_by_id.keys():
            vuln_found = True
            found_vuln = vulns_by_id[vulnId]

    # If data for the instance came back, we can end. Otherwise, continue to next subaccount
    if vulns_by_package:
        break

# Finally, output the results. Generate 2 files (3 if vulnId passed on commnd line and found in data)
# Files will be time stamped and saved in either named location from command line or in current working dir
if not vulns_by_package:
    print("No vulnerabilities returned for given host instanceId")
    exit(1)

current_time = datetime.now()
current_time_str = current_time.strftime("%Y-%m-%dT%H:%M:%S")

by_package_file = outputlocation + '/' + current_time_str + '_vulns_by_package.json'
by_id_file = outputlocation + '/' + current_time_str + '_vulns_by_id.json'

if vulnId is not None:
    if vuln_found:
        found_vuln_file = current_time_str + '_' + vulnId + '.json'
        with open(found_vuln_file, 'w') as json_file:
            json.dump(found_vuln, json_file, indent=2)
        print ('Information for ' + vulnId + ' saved to ' + found_vuln_file)
    else:
        print('!!' + vulnId + ' not found for instance ' + machineId)

with open(by_package_file, 'w') as json_file:
    json.dump(vulns_by_package, json_file, indent=2)
print('Vulnerabilities indexed by package saved to ' + by_package_file)

with open(by_id_file, 'w') as json_file:
    json.dump(vulns_by_id, json_file, indent=2)
print('Vulnerabilties indexed by VulnId saved to ' +  by_id_file)
