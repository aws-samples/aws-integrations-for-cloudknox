
#  Lambda for Control Tower Lifecyle Event Trigger with CloudKnox and AWS Control Tower
#  -  Uses CloudKnox Authenticate and Add Account APIs

# @kmmahaj
#
# @mneelka - CloudKnox Policy API
## License:
## This code is made available under the MIT-0 license. See the LICENSE file.


import json
import sys
import datetime
import boto3
import botocore
import datetime
import logging
import urllib.request
import time
import os
import random
from botocore.exceptions import ClientError

try:
    import liblogging
except ImportError:
    pass

import http.client
import mimetypes
import ssl


logger = logging.getLogger()
logger.setLevel(logging.INFO)
stackset_list = ['CloudKnoxMemberRolev1']
result = {"ResponseMetadata":{"HTTPStatusCode":"400"}}
       

## AWS Secrets Manager - retrieve secretstring
def get_secret_value(key='CloudKnoxSecretString'):
          secretsmanager = boto3.client('secretsmanager')
          secret_list = secretsmanager.list_secrets()['SecretList']
          output = {}
          for s in secret_list:
              if key in s.values():
                  output = secretsmanager.get_secret_value(SecretId=key)['SecretString']
          return(output)


##  Add Account CloudKnox API:
def addCloudKnoxAccount(apiId, accessToken, serviceId, timestamp,url,CloudKnoxSentryAccountId, accId, port):
    conn = http.client.HTTPSConnection(url, port)
    content_type = "application/json"
    print('inside addCloudKnoxAccount')
    print('apiId: '+ apiId )
    print('accessToken: '+ accessToken )
    print('serviceId: '+ serviceId )
    print('timestamp: '+ timestamp )
    print('url: ' + url)
    print('CloudKnoxSentryAccountId: ' + CloudKnoxSentryAccountId)
    print('accId: ' + accId)
    
    headers = {
      'X-CloudKnox-Access-Token': accessToken,
      'X-CloudKnox-API-Id': apiId,
      'X-CloudKnox-Service-Account-Id': serviceId,
      'X-CloudKnox-Timestamp-Millis': timestamp,
      'Content-Type': content_type
    }
    
    endTime = int(round(time.time() * 1000))
    startTime = endTime - (90*86400*1000)
    
    cloudknoxDict = {}
    cloudknoxDict['authorizationSystemId'] = CloudKnoxSentryAccountId
    cloudknoxDict['accountsToAdd'] = [{'id': accId,
                                       'roleName': 'IAM_R_KNOX_SECURITY_XA'}]

    payload = json.dumps(cloudknoxDict)

    print('payload: ' + payload)
    
    conn.request("POST", "/api/v2/organization/auth-systems/aws/add", payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_raw = data.decode()
    print('data_raw: ' + data_raw)
    dataResponse = json.loads(data.decode("utf-8"))

    return

## Authenticate CloudKnox API - Retrieve accessToken:
def getAccessToken(serviceId,timestamp,accessKey,secretKey,url,port):
    conn = http.client.HTTPSConnection(url, port)
    content_type = "application/json"
    print('serviceId-accessToken: '+ serviceId )
    print('timestamp-accessToken: '+ timestamp )
    print('accessKey-accessToken: '+ accessKey )
    print('secretKey-accessToken: '+ secretKey )
    print('url-accessToken: ' + url)

    headers = {
      'X-CloudKnox-Service-Account-Id': serviceId,
      'X-CloudKnox-Timestamp-Millis': timestamp,
      'Content-Type': content_type
    }

    cloudknoxDict = {}
    cloudknoxDict['serviceAccountId'] = serviceId
    cloudknoxDict['accessKey'] = accessKey
    cloudknoxDict['secretKey'] = secretKey

    payload = json.dumps(cloudknoxDict)
    print('payload-accessToken: ' + payload)
    
    conn.request("POST", "/api/v2/service-account/authenticate", payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_raw = data.decode()
    print('data_raw: ' + data_raw)
    dataResponse = json.loads(data.decode("utf-8"))
    print('accessToken: ' + dataResponse['accessToken'])
    return dataResponse['accessToken']

def lambda_handler(event, context):
    
    ## CloudKnox Details in Secrets Manager
    secretList = json.loads(get_secret_value('CloudKnoxSecretString'))
    serviceId=""
    apiId=""
    accessKey=""
    secretKey=""
    accessToken=""
    accountId=""
    url=""
    accessToken=""
    
    serviceId_key='serviceId'
    apiId_key='apiId'
    accessKey_key='accessKey'
    secretKey_key='secretKey'
    accountId_key= 'accountId'
    url_key='url'
     
    if serviceId_key in secretList:
        serviceId = secretList[serviceId_key]
    if apiId_key in secretList:
        apiId = secretList[apiId_key]
    if accessKey_key in secretList:
        accessKey = secretList[accessKey_key]
    if secretKey_key in secretList:
        secretKey = secretList[secretKey_key]
    if accountId_key in secretList:
        accountId = secretList[accountId_key]
    if url_key in secretList:
        url = secretList[url_key]

    millis = int(round(time.time() * 1000))
    timestamp = str(millis)
    
    accessToken = getAccessToken(serviceId,timestamp,accessKey,secretKey,url,443)
    print('accessToken is: ' + accessToken)

    masterAcct = event['account']
    CloudKnoxSentryAccountId = os.environ['CloudKnoxSentryAccountId']
    eventDetails = event['detail']
    regionName = eventDetails['awsRegion']
    eventName = eventDetails['eventName']
    srvEventDetails = eventDetails['serviceEventDetails']
    if eventName == 'CreateManagedAccount' or eventName == 'UpdateManagedAccount':
        newAccInfo = {}
        logger.info('Event Processed Sucessfully')
        if eventName == 'CreateManagedAccount':
            newAccInfo = srvEventDetails['createManagedAccountStatus']
        if eventName == 'UpdateManagedAccount':
            newAccInfo = srvEventDetails['updateManagedAccountStatus']
        cmdStatus = newAccInfo['state']
        if cmdStatus == 'SUCCEEDED':
            accId = newAccInfo['account']['accountId']
            cloudformation = boto3.client('cloudformation')
            for item in stackset_list:
                try:
                    print('ctlambda-apiId: '+ apiId )
                    print('ctlambda-eventName: ' + eventName)
                    print('ctlambda-accessToken: '+ accessToken )
                    print('ctlambda-serviceId: '+ serviceId )
                    print('ctlambda-timestamp: '+ timestamp )
                    print('ctlambda-url: ' + url)
                    print('ctlambda-CloudKnoxSentryAccountId: ' + CloudKnoxSentryAccountId)
                    print('ctlambda-regionName: ' + regionName)
                    print('ctlambda-StackSetName: ' + item)
                    print('ctlambda-accId: ' + accId)
                    result = cloudformation.create_stack_instances(StackSetName=item,Accounts=[accId], Regions=[regionName])
                    logger.info('Processed {} Sucessfully'.format(item))
                    addCloudKnoxAccount(apiId, accessToken, serviceId, timestamp, url,CloudKnoxSentryAccountId, accId, 443)
                except Exception as e:
                    logger.error('Unable to launch in:{}, REASON: {}'.format(item, e))
        else:
            logger.info('Unsucessful Event Recieved. SKIPPING :{}'.format(event))
            return(False)
    else:
        logger.info('Control Tower Event Captured :{}'.format(event))
  
    return 
