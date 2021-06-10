import json
import boto3
import sys
import os
import logging
import traceback
import requests
import base64
import urllib3
import botocore.exceptions as bce

logger = logging.getLogger()
logger.setLevel(logging.INFO)

urllib3.disable_warnings()

REGION = os.environ['AWS_REGION']
SSM_PARAMETER_CMDB_API_CLIENT_SECRET_NAME = "ApiClientSecretName"
SSM_PARAMETER_NUID_SECRET_NAME = "NuidSecretName"
SSM_PARAMETER_CMDB_API_REST_ENDPOINT = "CmdbApiEndpoint"
SSM_PARAMETER_FMSSO_ENDPOINT = "FmssoEndpoint"

def lambda_handler(event, context):
    eventType = event['detail-type']
    assetID = event['detail']['AssetId']
    if eventType == 'DistributionCreated':
        url = get_parameter(SSM_PARAMETER_CMDB_API_REST_ENDPOINT)
        token = get_sso_token()
        payload = "{\"query\":\"{\\r\\n bar(\\r\\n limit:10000\\r\\n){\\r\\n results{\\r\\n assetId\\r\\n externallyFacingIndicator\\n}\\n }\\r\\n}\"}"
        headers = {
            'Content-Type': 'application/json',
            'x-fnma-jws-token': token,
            'x-fnma-channel': 'api',
            'x-fnma-api-type': 'private'
                }
        try:
            response = requests.request("POST", url, headers=headers, data = payload, verify=False)
            result = json.loads(response.text)
        except bce.ClientError as error:
            raise(error)
        for i in result['data']['bar']['results']:
            try:
                logger.info(f'event: {event}')
                if i['assetId'] == assetID and i['externallyFacingIndicator'] == 'Yes':
                    logger.info(f'{assetID} is externally facing')
                    break
                elif i['assetId'] == assetID and i['externallyFacingIndicator'] == 'No':
                    sys.exit(f'{assetID} is not externally facing')
            except bce.ClientError as error:
                exception_type, exception_value, exception_traceback = sys.exc_info()
                traceback_string = traceback.format_exception(exception_type, exception_value, exception_traceback)
                err_msg = json.dumps({
                    "errorType": exception_type.__name__,
                    "errorMessage": str(exception_value),
                    "stackTrace": traceback_string
                })
                logger.error(err_msg)
        else:
            sys.exit('Asset ID not found')
    if eventType == 'DistributionUpdated':
        pass
    if eventType == 'DistributionDeleted':
        pass

def get_sso_token():
    fmsso_url = get_parameter(SSM_PARAMETER_FMSSO_ENDPOINT)
    nuid_secret = get_parameter(SSM_PARAMETER_NUID_SECRET_NAME)
    cmdb_secret = get_parameter(SSM_PARAMETER_CMDB_API_CLIENT_SECRET_NAME)
    nuid_auth = get_secret(nuid_secret)
    nuid_id = nuid_auth['username']
    nuid_password = nuid_auth['password']
    cmdb_auth = get_secret(cmdb_secret)
    cmdb_id = cmdb_auth['client-id']
    cmdb_pw = cmdb_auth['client-secret']
    logger.info('Retrieving SSO Token...')
    auth = 'Basic ' + str(base64.b64encode((cmdb_id + ':' + cmdb_pw).encode('utf-8')).decode('utf-8'))
    payload = "grant_type=password&username=" + nuid_id + "&password=" + nuid_password
    headers = {
        'Content-Type': "application/x-www-form-urlencoded",
        'Authorization': auth
    }
    try:
        response = requests.request("POST", fmsso_url, data=payload, headers=headers)
        logger.info('SSO Token Successfully retrieved')
        return json.loads(response.text)['access_token']
    except bce.ClientError as error:
                raise(error)

def get_parameter(parameter_name):
    ssm = boto3.client(service_name='ssm', region_name=REGION)
    try:
        response = ssm.get_parameters(Names=[parameter_name],WithDecryption=True)
        for parameter in response['Parameters']:
            return parameter['Value'] 
    except bce.ClientError as error:
        raise(error) 

def get_secret(secret_name):
    client = boto3.client(service_name='secretsmanager', region_name=REGION)
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret = get_secret_value_response['SecretString']
        return json.loads(secret)
    except bce.ClientError as error:
        raise(error)
