'''
# This is an ugly python code which authenticates with CS Falcon API and fetches 'new' detections using filters and
# sends that info into a Slack Channel using a Webhook
#
# Sensitive information is stored in AWS SSM Parameter Store and retrieved appropriately.
#
# API & Code References:
# https://falcon.crowdstrike.com/support/documentation/46/crowdstrike-oauth2-based-apis
# https://falcon.crowdstrike.com/support/documentation/86/detections-monitoring-apis
# Slack Webhook Python API Post - https://gist.github.com/devStepsize/b1b795309a217d24566dcc0ad136f784
#
# Pre-requisite for this code to work is that the detection status is 'new'. As fas as there is a 'new' detection this code sends out a slack notification.
# It is the responders responsibility to change the status of the detection once we engage or kick off our incident response.
# 
'''


import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import json
import boto3
from botocore.exceptions import ClientError

from urllib.request import Request, urlopen, URLError, HTTPError

# Retrieves the Sensitive information - CS Falcon API Client ID & Secret. Slack Webhook
def get_ssm_parameters():

	ssm = boto3.client('ssm',region_name='us-east-1')
	response = ssm.get_parameters(
			Names=[
				'/CSFalcon/APIUser', '/CSFalcon/APIPass', '/CSFalcon/HOOKURL'
			],
			WithDecryption=True
	)
	
	return(response['Parameters'][1]['Value'], response['Parameters'][0]['Value'], response['Parameters'][2]['Value'])
	
	
# Function for adding Detection ID to 
def put_state(detectionid):
	
	table_name = 'csfalcondetections'
	client = boto3.client('dynamodb')
	
	put_item_response = client.put_item(
	TableName = table_name,
	Item={
		'detectionid': {
			'S': detectionid,
			}
		}
	)
	
def get_state(detectionid):

	table_name = 'csfalcondetections'
	client = boto3.client('dynamodb')
	
	try:
		get_item_response = client.get_item(
		TableName = table_name,
		Key={
			'detectionid': {
				'S': detectionid,
				}
			}
		)
		
		if 'Item' in get_item_response.keys():
			item = get_item_response["Item"]
			return(item['detectionid']['S'])
		else:
			return []
		
	except ClientError as e:
		return e

# Sends the information to Slack using the webhook and attachments over HTTP POST
def alertonslack(hostname, externalip, localip, filename, tactic, technique, severity, hookurl, permalink):

	#ENCRYPTED_HOOK_URL = os.environ.get('ENCRYPTED_HOOK_URL', None) 
	#HOOK_URL = "https://" + boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext']
	#HOOK_URL = os.environ.get('HOOK_URL', None)
	
	attachments = [
		{
		#"fallback": Message,
		"attachment_type": "default",
		"fields": [
			#{"title": "Message", "value": "Crowdstrike Notification", "short": False},
			{"title": "Hostname", "value": hostname, "short": True},
			{"title": "Severity", "value": severity, "short": True},
			{"title": "External IP", "value": externalip, "short": True},
			{"title": "Local IP", "value": localip, "short": True},
			{"title": "Filename", "value": filename, "short": True},
			{"title": "Type", "value": tactic, "short": True},
			{"title": "Technique", "value": technique, "short": True},
			{"title": "Link", "value": permalink, "short": False},
				],
		"color": "#ad0614"
		}
	]

	slack_message = {
		"text": "Detection",
		'attachments': attachments,
		'username': "Crowdstrike Falcon",
		'icon_emoji': ':robot_face:'
}

	try:
		request = Request(hookurl, method='POST').add_header('Content-Type', 'application/json')
		data = json.dumps(slack_message).encode()
		response = urlopen(request, data)

	except HTTPError as e:
		print("Request failed: " + e.code + " " + e.reason)
	except URLError as e:
		print("Server connection failed: " + e.reason) 		


def main(event, context):

	# OAUTH2 Get Token API
	token_url = "https://api.crowdstrike.com/oauth2/token"
	# Get Detections CS Falcon API
	api_url = "https://api.crowdstrike.com/detects/queries/detects/v1"
	# Get Summaries of Detection
	summaries_api = "https://api.crowdstrike.com/detects/entities/summaries/GET/v1"

	#client (application) credentials on Falcon API 
	client_id, client_secret, hookurl = get_ssm_parameters()
	#step A, B - single call with client credentials as the basic auth header - will return access_token
	data = {'grant_type': 'client_credentials'}
	access_token_response = requests.post(token_url, data=data, verify=False, allow_redirects=False, auth=(client_id, client_secret))
	tokens = json.loads(access_token_response.text)
	
	filter = ("status:'new'")
	payload = {'filter':"{}".format(filter)}

	#step B - with the returned access_token we can make as many calls as we want
	api_call_headers = {'Authorization': 'Bearer ' + tokens['access_token'], 'Content-type':'application/json', 'Accept':'application/json'}
	api_call_response = requests.get(api_url, headers=api_call_headers, verify=False, params=payload)

	data = api_call_response.json()

	for key in data.keys():
		if key == 'resources':
			for detectionid in range(len(data[key])):
				# Checking Detection ID is our State Machine if this detection was already notified.
				state = get_state(data[key][detectionid])
				
				# We use DynamoDB for this purpose.
				if data[key][detectionid] in state:
						print("DetectionID already in state...\n")
						continue
				else:
					print("New Detection!\nProceeding with Slack Notification")
				
					# Splitting the detection id to gather the permalink for the CS Falcon UI to be sent out in the Slack notification
					fh = data[key][detectionid].split(':')[1]
					sh = data[key][detectionid].split(':')[2]
					
					permalink = "https://falcon.crowdstrike.com/activity/detections/detail/" + fh + '/' + sh
					
					payload = { "ids": [data[key][detectionid]] }
					json_payload = json.dumps(payload)
					r = requests.post(summaries_api, headers=api_call_headers, verify=False, data = json_payload)
					
					metadata = r.json()
					
					for item in metadata.keys():
						if item == 'resources':
							for summary in range(len(metadata[item])):
								detection = metadata[item][summary]
	
								device = detection["device"]
								behaviors = detection["behaviors"]
								severity = detection["max_severity_displayname"]
								hostname = device["hostname"]
								externalip = device["external_ip"]
								localip = device["local_ip"]
								
								for behavior in range(len(behaviors)):
									filename = behaviors[behavior].get('filename')
									tactic = behaviors[behavior].get('tactic')
									technique = behaviors[behavior].get('technique')
	
									alertonslack(hostname, externalip, localip, filename, tactic, technique, severity, hookurl, permalink)
									put_state(data[key][detectionid])