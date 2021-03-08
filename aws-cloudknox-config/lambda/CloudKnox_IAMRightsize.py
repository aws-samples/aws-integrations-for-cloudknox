# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#  Lambda for IAM Rightsizing with CloudKnox and AWS Config
#  - Creates new IAM Policy and detaches existing policies for IAM user
#  - New IAM Policy created based on policy data retrieved from CloudKnox JEP Controller


# @kmmahaj
#
# @mneelka/@anowar-cloudknox  - CloudKnox API

import json
import boto3
from botocore.exceptions import ClientError
import time
import logging
import http.client

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)
session = boto3.session.Session()
curr_time = int(round(time.time() * 1000))
ck_config_name = 'CloudKnoxSecretString'
ck_endpoint_port = 443
allowed_ck_config = ('serviceId', 'apiId', 'accessKey', 'secretKey', 'accountId', 'url')


def get_iam_user_name(iam_user_id):
    """
    get iam user resource name
    :param iam_user_id: iam user id
    :return: iam_user_name: iam user name
    """
    client = session.client(service_name='config')
    iam_user_name = ''

    try:
        list_discovered_resources_resp = client.list_discovered_resources(
            resourceType='AWS::IAM::User',
            resourceIds=[iam_user_id]
        )
    except ClientError as e:
        logger.error(f"error while executing list_discovered_resources, {e}")
        raise Exception()
    else:
        iam_user_name = list_discovered_resources_resp['resourceIdentifiers'][0]['resourceName']
    finally:
        logger.info(f'iam user {iam_user_id} resource name {iam_user_name}')
        return iam_user_name


def get_secret_value(secret_name):
    """
    get secret value from AWS Secrets Manager
    :param secret_name: name of the secret passed
    :return secret_value: value of the secret passed
    """
    client = session.client(service_name='secretsmanager')
    secret_value = ''
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        logger.error(f"error while executing get_secret_value, {e}")
        raise Exception()
    else:
        secret_value = get_secret_value_response['SecretString'] if 'SecretString' in get_secret_value_response else ''
    finally:
        return secret_value


def get_cloudknox_config():
    """
    get cloudknox config, throws exception if invalid
    :return config: cloudknox config dict
    """
    config = json.loads(get_secret_value(ck_config_name))
    for key in config:
        if not config.get(key, ''):
            logger.error(f"either key {key} do not exist, or non empty value found")
            raise Exception()
    return config


def get_access_token(ck_config=None):
    """
    Authenticate CloudKnox API - Retrieve accessToken:
    :param ck_config: cloudknox config dict
    :return policy: cloudknox api token
    """
    assert isinstance(ck_config, dict), 'ck config must be of type dict'
    conn = http.client.HTTPSConnection(ck_config['url'], ck_endpoint_port)

    headers = {
        'X-CloudKnox-Service-Account-Id': ck_config['serviceId'],
        'X-CloudKnox-Timestamp-Millis': str(curr_time),
        'Content-Type': 'application/json'
    }

    cloudknox_dict = {
        'serviceAccountId': ck_config['serviceId'],
        'accessKey': ck_config['accessKey'],
        'secretKey': ck_config['secretKey']
    }
    payload = json.dumps(cloudknox_dict)

    conn.request("POST", "/api/v2/service-account/authenticate", payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_response = json.loads(data.decode("utf-8"))
    token = data_response['accessToken']
    if not token:
        raise Exception()
    return token


def get_cloudknox_remediation_policies(access_token, user_arn, ck_config=None):
    """
    calls cloudknox api to get the list of policies as per usage
    :param access_token: cloudknox api token
    :param user_arn: cloudknox api token
    :param ck_config: cloudknox service id
    :return cloudknox_remediated_policies: cloudknox remediated policy documents
    """
    assert isinstance(ck_config, dict), 'ck config must be of type dict'
    conn = http.client.HTTPSConnection(ck_config['url'], ck_endpoint_port)
    headers = {
        'X-CloudKnox-Access-Token': access_token,
        'X-CloudKnox-API-Id': ck_config['apiId'],
        'X-CloudKnox-Service-Account-Id': ck_config['serviceId'],
        'X-CloudKnox-Timestamp-Millis': str(curr_time),
        'Content-Type': "application/json"
    }

    cloudknox_dict = {
        'authSystemInfo': {'id': ck_config['accountId'], 'type': 'AWS'},
        'identityType': 'USER',
        'identityIds': [user_arn],
        'aggregation': {'type': 'SUMMARY'},
        'requestParams': {'scope': None, 'resource': None, 'resources': None, 'condition': None},
        'filter': {'historyDays': 90}
    }
    payload = json.dumps(cloudknox_dict)
    logger.info(f'remediation policy request payload {payload}')

    conn.request("POST", "/api/v2/role-policy/new", payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_raw = data.decode()
    logger.info(f'raw data received for remediation policy {data_raw}')
    response = json.loads(data.decode("utf-8"))
    cloudknox_remediated_policies = response['data']

    if len(response['data']) == 0 or response.get('errorCode'):
        default_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Sid': 'AllowIAM',
                'Effect': 'Allow',
                'Action': ['iam:CreateRole'],
                'Resource': '*'
            }]
        }
        policy_data = {'policyName': "ck_activity_test", 'policy': default_policy}
        data_list = [{}] * 1
        data_list[0] = policy_data
        cloudknox_remediated_policies = data_list

    return cloudknox_remediated_policies


def get_remediated_policy_list(user_name, ck_remediated_policies=None):
    """
    get iam policies and names based of least privileged principle
    :param user_name: iam user name
    :param ck_remediated_policies: list of policies from cloudknox API
    :return iam_policies: iam policy dict
    """
    iam_policies = {}
    count = 1
    for ck_policy in ck_remediated_policies:
        iam_policy_doc = json.dumps(ck_policy['policy'])
        policy_name = '-'.join(['cloudknox', 'remediated', 'policy', user_name, str(curr_time), str(count)])
        logger.info(f'policy {policy_name} with document {iam_policy_doc}')
        count += 1
        iam_policies[policy_name] = iam_policy_doc
    return iam_policies


def attach_remediated_iam_policies(client, iam_user, iam_policies=None):
    """
    attach policies to iam user
    :param client: iam client
    :param iam_user: ima user
    :param iam_policies: iam polices to be attached
    """
    for policy_name, policy_doc in iam_policies.items():
        logger.info(f'create managed policy {policy_name}')
        create_policy_resp = client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_doc
        )
        logger.info(f'create_policy for {policy_name} response {create_policy_resp}')
        attach_user_policy_resp = client.attach_user_policy(
            UserName=iam_user,
            PolicyArn=create_policy_resp['Policy']['Arn']
        )
        logger.info(f'attach_user_policy for {policy_name} response {attach_user_policy_resp}')
        time.sleep(.1)


def clean_unused_iam_policies(client, iam_user, remediated_iam_policy_list=None):
    """
    clean excess unused permissions from user
    :param client: iam client
    :param iam_user: iam user
    :param remediated_iam_policy_list: list of required policy names
    """
    list_attached_user_policies_resp = client.list_attached_user_policies(UserName=iam_user)
    logger.info(f'list_attached_user_policies_resp {list_attached_user_policies_resp}')
    if len(list_attached_user_policies_resp['AttachedPolicies']) > 0:
        for policy in list_attached_user_policies_resp['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            if policy['PolicyName'] not in remediated_iam_policy_list:
                logger.info(f'policy {policy_arn} to be detached')
                detach_user_policy_resp = client.detach_user_policy(UserName=iam_user, PolicyArn=policy_arn)
                logger.info(f'detach_user_policy for {policy_arn} response {detach_user_policy_resp}')
            else:
                logger.info(f'policy {policy_arn} skipped')

    list_groups_for_user_resp = client.list_groups_for_user(UserName=iam_user)
    logger.info(f'list_groups_for_user_resp {list_groups_for_user_resp}')
    if len(list_groups_for_user_resp['Groups']) > 0:
        for group in list_groups_for_user_resp['Groups']:
            group_name = group['GroupName']
            logger.info(f'group {group_name} to be detached')
            remove_user_from_group_resp = client.remove_user_from_group(GroupName=group_name, UserName=iam_user)
            logger.info(f'remove_user_from_group for {group_name} response {remove_user_from_group_resp}')

    list_user_policies_resp = client.list_user_policies(UserName=iam_user)
    logger.info(f'list_user_policies_resp {list_user_policies_resp}')
    if len(list_user_policies_resp['PolicyNames']) > 0:
        for policy in list_user_policies_resp['PolicyNames']:
            logger.info(f'user inline policy {policy} to be deleted')
            delete_user_policy_resp = client.delete_user_policy(UserName=iam_user, PolicyName=policy)
            logger.info(f'delete_user_policy for {policy} response {delete_user_policy_resp}')


def lambda_handler(event, context):
    iam_user_id = event['parameterValue']
    assert iam_user_id != '', 'iam user resource id cannot be empty'
    logger.info(f'iam user resource id {iam_user_id}')

    iam_user = get_iam_user_name(iam_user_id)
    assert iam_user != '', 'iam user name cannot be empty'
    logger.info(f'iam user name {iam_user} for resource id {iam_user_id}')

    ck_config = get_cloudknox_config()
    logger.info(f'cloudknox config successfully retrieved from secrets')
    access_token = get_access_token(ck_config)
    logger.info(f'cloudknox temporary access token successfully retrieved')

    user_arn = 'arn:aws:iam::' + ck_config['accountId'] + ':user/' + iam_user
    ck_remediated_policies = get_cloudknox_remediation_policies(access_token, user_arn, ck_config)

    if len(ck_remediated_policies) < 1:
        logger.info(f'received empty list of iam_policies, aborting remediation')
        return

    iam_policies = get_remediated_policy_list(iam_user, ck_remediated_policies)
    logger.info(f'received iam_policies dict {iam_policies}')
    iam_client = session.client(service_name='iam')
    attach_remediated_iam_policies(iam_client, iam_user, iam_policies)
    clean_unused_iam_policies(iam_client, iam_user, iam_policies.keys())
