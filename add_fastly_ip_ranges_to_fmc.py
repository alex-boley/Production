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

 # Variables 
server = "https://pr2fmc01.net.ithaka.org"
username = "api"
password = config.get("api","api_password")
data = ''

# Global variables to be used later on
now = datetime.datetime.now()
current_fastly_list = []
new_fastly_list = []

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
            print("****************************GET successful for " + objectname + " in " + object_type + "." + "Response data --> ")
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
                    if device['device']['name'] == 'pr1fpha' or 'aa1fpha':
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
               

# This will go to fastly's webpage that lists its ip ranges in json format, this returns an array of dicitionaries called "literals" that is needed by the API for creating the network group
def get_fastly_ip_ranges():
    literals = []

    ip_ranges = requests.get('https://api.fastly.com/public-ip-list').json()['addresses']
    if ip_ranges == "":
        print('No IPs recieved from fastly')
        sys.exit()

    for item in ip_ranges:
        literals.append({'type': 'Network', 'value': item })

    return literals

def put_new_fastly_net_all(object_type, objectname):
    # Create the put data by erasing all of its networks and replacing them all from the fastly website json file
    # We will also do a comparsion of ip's being removed and added so this can be emailed to the network team
    # and documented
    put_data = get_object(object_type, objectname)
    put_data.pop('links', None)

    current_fastly_list = put_data['literals']

    put_data['literals'] = []
    put_data['literals'] = get_fastly_ip_ranges()
    
    new_fastly_list = put_data['literals']
    new_fastly_list_compare = []
    current_fastly_list_compare = []

    for network in new_fastly_list:
        for ip in network:
            # The FMC removes the /32 in the object literal, so here we erase the /32 from fastly for comparsions sake
            if network['value'].find('/32') != -1:
                new_fastly_list_compare.append(network['value'][:-3])
            else:
                new_fastly_list_compare.append(network['value'])

    for network in current_fastly_list:
        for ip in network:
            current_fastly_list_compare.append(network['value'])

    added_ips = list(set(new_fastly_list_compare) - set(current_fastly_list_compare))
    removed_ips = list(set(current_fastly_list_compare) - set(new_fastly_list_compare))

    if added_ips and removed_ips == '':
        print('empty lists...Error!')
        sys.exit()

    if added_ips == removed_ips:
        print('no changes')
        #sys.exit()

    Send email to network engineers with the changes being made
    sender = 'FMC_Automation@ithaka.org'
    receivers = ['alex.boley@ithaka.org, robert.Kupiec@ithaka.org, jason.baker@ithaka.org']

    message = """From: FMC_Automation@ithaka.org
To: jason.baker@ithaka.org, alex.boley@ithaka.org, robert.Kupiec@ithaka.org
Subject: FMC FASTLY_NET_ALL Network Group Update

These ip's are being added to the FASTLY_NET_ALL Network Group:
""" + ', '.join(added_ips) + """
\n These ip's are being removed from the FASTLY_NET_ALL Network Group:
""" + ', '.join(removed_ips)

    

    try:
       smtpObj = smtplib.SMTP('smtp.ithaka.org')
       smtpObj.sendmail(sender, receivers, message)
       print("Successfully sent email")
    except SMTPException:
       print("Error: unable to send email")

    with open('/home/netadmin/prod/scripts/fastly_update_log_file.txt', 'a+') as fastly_update_log_file:
                fastly_update_log_file.write("updated on " + str(now) + "\n")

    Finally update the object in the FMC

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

#################################
######## Main Program ###########
#################################

put_new_fastly_net_all('networkgroups', 'FASTLY_NET_ALL')

deploy_changes_in_fmc()
