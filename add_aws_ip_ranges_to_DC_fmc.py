import json
import sys
import requests
import configparser
import datetime
import smtplib
import time

# To read stored protected password
config = configparser.ConfigParser()
config.read("/etc/.config.txt")

# To check when this was last updated and compare to when AWS updated their IP ranges
last_update = configparser.ConfigParser()
last_update.read("/home/netadmin/prod/scripts/DC_aws_range_last_updated.txt")

 # Variables 
server = "https://10.102.254.100"
username = "api"
password = config.get("api","api_password")
data = ''

# Global variables to be used later on
now = datetime.datetime.now()
current_aws_list = []
new_aws_list = []

### Main functions ###

# This authorizes us to interact with the FMC API
def generate_token():
    r = None
    headers = {'Content-Type': 'application/json'}
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = server + api_auth_path
    try:
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")
            sys.exit()
    except Exception as err:
        print ("Error in generating auth token --> "+str(err))
        sys.exit()
 
    headers['X-auth-access-token']=auth_token
    return headers


# This gets the objet ID based on the name of the object and returns the ID. The object ID is required by the API for getting the json information on the object
def get_object_id(object_type, objectname):
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/" + object_type
    limit = "?limit=1000"
    url = server + api_path + limit
    if (url[-1] == '/'):
        url = url[:-1]

    try:
        r = requests.get(url, headers=generate_token(), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("*******************************GET successful for ObjectID.")
            json_resp = json.loads(resp)
            names = json_resp['items']
            for name in names:
                if (name['name'] == objectname):
                    objectid = name['id']
                    print(objectid)
                    return objectid
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()


# This gets the object by name and returns all of its "objects" this could also be changed to "literals" if it contains them
def get_object(object_type, objectname):
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/" + object_type + "/" + get_object_id(object_type, objectname)
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1] 

    try:
        r = requests.get(url, headers=generate_token(), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("****************************GET successful for " + objectname + " in " + object_type + "." + " Response data --> ")
            json_resp = json.loads(resp)
            return json_resp
            #print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()


def deploy_changes_in_fmc():
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deployabledevices?expanded=true"
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    try:
        r = requests.get(url, headers=generate_token(), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("*******************************GET successful for deployabledevices.")
            json_resp = json.loads(resp)
            devices = json_resp['items']
            for device in devices:
                if device['canBeDeployed'] == True:
                    if device['device']['name'] == 'aa2-vm-ftd-1' or 'pr2-vm-ftd-1':
                        push_deployment_to_device(device['version'], device['device']['id'])
                        time.sleep(1200)
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()

def push_deployment_to_device(version, device_id):
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deploymentrequests"
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    post_data = {
      "type": "DeploymentRequest",
      "version": version,
      "forceDeploy": True,
      "ignoreWarning": True,
      "deviceList": [
        device_id
      ]
    }
    try:
        r = requests.post(url, data=json.dumps(post_data), headers=generate_token(), verify=False)
        status_code = r.status_code
        resp = r.text
        print("Status code is: "+str(status_code))
        if status_code == 201 or status_code == 202:
            print ("Post was successful...")
            json_resp = json.loads(resp)
            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else :
            r.raise_for_status()
            print ("Error occurred in POST --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r: r.close()
               

# This will go to amazons webpage that lists its ip ranges in json format, this returns an array of dicitionaries called "literals" that is needed by the API for creating the network group
# **** IPV6 has been commented out below since it is not needed ****
def get_amazon_ip_ranges():
    literals = []

    ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['prefixes']
    #ipv6_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['ipv6_prefixes']
    if ip_ranges == "":
        print('No IPs recieved from Amazon')
        sys.exit()

    for item in ip_ranges:
        if 'us-east-' in item['region'] and "AMAZON" in item['service']:
            literals.append({'type': 'Network', 'value': item['ip_prefix']})
    

    #print("******** \n\n  There is " + str(len(literals)) + " ip ranges added.\n\n ********")
    # for item in ipv6_ranges:
    #     if 'us-east' in item['region']:
    #         literals.append({'type': 'Network', 'value': item['ipv6_prefix']})
    #print(literals)
    return literals

def put_new_aws_east(object_type, objectname):
    # Create the put data by erasing all of its networks and replacing them all from the AWS website json file
    # We will also do a comparsion of ip's being removed and added so this can be emailed to the network team
    # and documented
    put_data = get_object(object_type, objectname)
    put_data.pop('links', None)

    current_aws_list = put_data['literals']

    put_data['literals'] = []
    put_data['literals'] = get_amazon_ip_ranges()
    
    new_aws_list = put_data['literals']
    new_aws_list_compare = []
    current_aws_list_compare = []

    for network in new_aws_list:
        for ip in network:
            # The FMC removes the /32 in the object literal, so here we erase the /32 from AWS for comparsions sake
            if network['value'].find('/32') != -1:
                new_aws_list_compare.append(network['value'][:-3])
            else:
                new_aws_list_compare.append(network['value'])

    for network in current_aws_list:
        for ip in network:
            current_aws_list_compare.append(network['value'])

    added_ips = list(set(new_aws_list_compare) - set(current_aws_list_compare))
    removed_ips = list(set(current_aws_list_compare) - set(new_aws_list_compare))

    print (removed_ips, added_ips)

    if added_ips == [] and removed_ips == []:
        sys.exit()
    

    # Send email to network engineers with the changes being made
    sender = 'DC_FMC_Automation@ithaka.org'
    receivers = ['alex.boley@ithaka.org, robert.Kupiec@ithaka.org, jason.baker@ithaka.org']

    message = """From: DC_FMC_Automation@ithaka.org
To: jason.baker@ithaka.org, alex.boley@ithaka.org, robert.Kupiec@ithaka.org
Subject: DC FMC AWS-EAST Network Group Update

These ip's are being added to the AWS-EAST Network Group:
""" + ', '.join(added_ips) + """
\n These ip's are being removed from the AWS-EAST Network Group:
""" + ', '.join(removed_ips)

    try:
       smtpObj = smtplib.SMTP('smtp.ithaka.org')
       smtpObj.sendmail(sender, receivers, message)
       print("Successfully sent email")
    except SMTPException:
       print("Error: unable to send email")

    # Finally update the object in the FMC

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/" + get_object_id(object_type, objectname)
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    try:
        r = requests.put(url, data=json.dumps(put_data), headers=generate_token(), verify=False)
        status_code = r.status_code
        resp = r.text
        print("Status code is: "+str(status_code))
        if status_code == 200:
            json_resp = json.loads(resp)
        else :
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r: r.close()

def check_new_ip_updates():
    last_updated = last_update.get("date","last_updated")
    ip_ranges_updated_on = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['createDate']
    if ip_ranges_updated_on == last_updated:
        sys.exit()
    else:
        last_update.set("date","last_updated", ip_ranges_updated_on)
        with open('/home/netadmin/prod/scripts/DC_aws_range_last_updated.txt', 'w') as configfile:
            last_update.write(configfile)

        with open('/home/netadmin/prod/scripts/DC_aws_update_log_file.txt', 'a+') as aws_update_log_file:
                aws_update_log_file.write("updated on " + str(now) + "\n")

#################################
######## Main Program ###########
#################################

check_new_ip_updates()

put_new_aws_east('networkgroups', 'AWS-EAST')

deploy_changes_in_fmc()
