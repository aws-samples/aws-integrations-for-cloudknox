""" Lambda for Control Tower Lifecyle Event Trigger with CloudKnox and AWS Control Tower """
#  Lambda for Control Tower Lifecyle Event Trigger with CloudKnox and AWS Control Tower
#  -  Uses CloudKnox Authenticate and Add Account APIs

# @kmmahaj
#
# @mneelaka - CloudKnox Policy API
## License:
## This code is made available under the MIT-0 license. See the LICENSE file.


import json
import logging
import time
import os
import http.client
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)
stackset_list = ['CloudKnoxMemberRolev1']
result = {"ResponseMetadata":{"HTTPStatusCode":"400"}}

## AWS Secrets Manager - retrieve secretstring
def get_secret_value(key='CloudKnoxSecretString'):
    """Get secret value."""
    secretsmanager = boto3.client('secretsmanager')
    secret_list = secretsmanager.list_secrets()['SecretList']
    output = {}
    for secret in secret_list:
        if key in secret.values():
            output = secretsmanager.get_secret_value(SecretId=key)['SecretString']
    return output

##  Add Account CloudKnox API:
def add_cloudknox_account(api_id,access_token,service_id,timestamp,url,
			cloudknox_sentry_account_id,acc_id,port):
    """Add CloudKnox account."""
    conn = http.client.HTTPSConnection(url, port)
    content_type = "application/json"
    print('inside add_cloudknox_account')
    print('api_id: '+ api_id )
    print('accessToken: '+ access_token )
    print('serviceId: '+ service_id )
    print('timestamp: '+ timestamp )
    print('url: ' + url)
    print('CloudKnoxSentryAccountId: ' + cloudknox_sentry_account_id)
    print('accId: ' + acc_id)

    headers = {
      'X-CloudKnox-Access-Token': access_token,
      'X-CloudKnox-API-Id': api_id,
      'X-CloudKnox-Service-Account-Id': service_id,
      'X-CloudKnox-Timestamp-Millis': timestamp,
      'Content-Type': content_type
    }

    cloudknox_dict = {}
    cloudknox_dict['authorizationSystemId'] = cloudknox_sentry_account_id
    cloudknox_dict['accountsToAdd'] = [{'id': acc_id,
                                        'roleName': 'IAM_R_KNOX_SECURITY_XA'}]

    payload = json.dumps(cloudknox_dict)

    print('payload: ' + payload)

    conn.request("POST", "/api/v2/organization/auth-systems/aws/add", payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_raw = data.decode()
    print('data_raw: ' + data_raw)
    json.loads(data.decode("utf-8"))

## Authenticate CloudKnox API - Retrieve accessToken:
def get_access_token(service_id,timestamp,access_key,secret_key,url,port):
    """Get CloudKnox access token."""
    conn = http.client.HTTPSConnection(url, port)
    content_type = "application/json"
    print('serviceId-accessToken: '+ service_id )
    print('timestamp-accessToken: '+ timestamp )
    print('accessKey-accessToken: '+ access_key )
    print('secretKey-accessToken: '+ secret_key )
    print('url-accessToken: ' + url)

    headers = {
      'X-CloudKnox-Service-Account-Id': service_id,
      'X-CloudKnox-Timestamp-Millis': timestamp,
      'Content-Type': content_type
    }

    cloudknox_dict = {}
    cloudknox_dict['serviceAccountId'] = service_id
    cloudknox_dict['accessKey'] = access_key
    cloudknox_dict['secretKey'] = secret_key

    payload = json.dumps(cloudknox_dict)
    print('payload-accessToken: ' + payload)

    conn.request("POST", "/api/v2/service-account/authenticate", payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_raw = data.decode()
    print('data_raw: ' + data_raw)
    data_response = json.loads(data.decode("utf-8"))
    print('accessToken: ' + data_response['accessToken'])
    return data_response['accessToken']

def lambda_handler(event, context):
    """Handle new account create."""

    ## CloudKnox Details in Secrets Manager
    secret_list = json.loads(get_secret_value('CloudKnoxSecretString'))
    service_id=""
    api_id=""
    access_key=""
    secret_key=""
    url=""

    service_id_key='serviceId'
    api_id_key='apiId'
    access_key_key='accessKey'
    secret_key_key='secretKey'
    url_key='url'

    if service_id_key in secret_list:
        service_id = secret_list[service_id_key]
    if api_id_key in secret_list:
        api_id = secret_list[api_id_key]
    if access_key_key in secret_list:
        access_key = secret_list[access_key_key]
    if secret_key_key in secret_list:
        secret_key = secret_list[secret_key_key]
    if url_key in secret_list:
        url = secret_list[url_key]

    millis = int(round(time.time() * 1000))
    timestamp = str(millis)

    access_token = get_access_token(service_id,timestamp,access_key,secret_key,url,443)
    print('accessToken is: ' + access_token)

    cloudknox_sentry_account_id = os.environ['CloudKnoxSentryAccountId']
    event_details = event['detail']
    region_name = event_details['awsRegion']
    event_name = event_details['eventName']
    srv_event_details = event_details['serviceEventDetails']
    if event_name == 'CreateManagedAccount' or event_name == 'UpdateManagedAccount':
        new_acc_info = {}
        logger.info('Event Processed Sucessfully')
        if event_name == 'CreateManagedAccount':
            new_acc_info = srv_event_details['createManagedAccountStatus']
        if event_name == 'UpdateManagedAccount':
            new_acc_info = srv_event_details['updateManagedAccountStatus']
        cmd_status = new_acc_info['state']
        if cmd_status == 'SUCCEEDED':
            acc_id = new_acc_info['account']['accountId']
            cloudformation = boto3.client('cloudformation')
            for item in stackset_list:
                try:
                    print('ctlambda-apiId: '+ api_id )
                    print('ctlambda-eventName: ' + event_name)
                    print('ctlambda-accessToken: '+ access_token )
                    print('ctlambda-serviceId: '+ service_id )
                    print('ctlambda-timestamp: '+ timestamp )
                    print('ctlambda-url: ' + url)
                    print('ctlambda-CloudKnoxSentryAccountId: ' + cloudknox_sentry_account_id)
                    print('ctlambda-regionName: ' + region_name)
                    print('ctlambda-StackSetName: ' + item)
                    print('ctlambda-accId: ' + acc_id)
                    cloudformation.create_stack_instances(StackSetName=item,
							  Accounts=[acc_id], Regions=[region_name])
                    logger.info('Processed %s Sucessfully', item)
                    add_cloudknox_account(api_id, access_token, service_id, timestamp, url,
					cloudknox_sentry_account_id, acc_id, 443)
                except Exception as e:
                    logger.error('Unable to launch in:%s, REASON: %s', item, e)
        else:
            logger.info('Unsucessful Event Received. SKIPPING :%s', event)
            return False
    else:
        logger.info('Control Tower Event Captured :%s', event)
