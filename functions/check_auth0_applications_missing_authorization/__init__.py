import socket
import hashlib
from typing import List, Dict
import requests  # pip install requests
import yaml  # pip install PyYAML
import boto3

AUTH0_AUDIENCE = 'auth.mozilla.auth0.com'


def get_temp_client_id_ignore_list():
    """Fetch a list of client IDs from multiple SSM parameter store parameters

    This is a list of client_ids of existing clients that have no authorization
    defined in apps.yml. These existing clients should be examined and if they
    are meant to allow everyone in at stage 1 authorization, then explicit
    entries in apps.yml should be created for them permitting the "everyone"
    group access to them.

    This method can be removed from this tool once this temporary list is
    empty.

    This method fetches multiple parameter store parameters because the size
    exceeds the 4096 character max. Each parameter is a comma delimited list.

    :return: List of client_ids
    """
    client = boto3.client('ssm')
    temp_client_id_ignore_list = []
    i = 0
    while True:
        i += 1
        try:
            response = client.get_parameter(
                Name=f'/iam/check_auth0_applications_missing_authorization/production/temp_client_id_ignore_list/{i}')
            temp_client_id_ignore_list.extend(
                response['Parameter']['Value'].split(','))
        except client.exceptions.ParameterNotFound:
            break
    return temp_client_id_ignore_list


def alert(source: str, pagerduty_integration_key: str, clients: List[Dict]):
    """Send a PagerDuty alert about clients missing authorization configs

    :param str source: The source of any alerts. This will help those receiving
        the alert to determine where it came from.
    :param str pagerduty_integration_key: The PagerDuty API key used to send
        the alert to PagerDuty
    :param list clients: List of dicts with details about each Auth0 client
    :return:
    """

    alert_body = (
        'The following new Auth0 client(s)/app(s) have been found but are '
        'missing from "apps.yml" authorization configuration. Entries must be '
        'created in "apps.yml" to assert what groups should have access to '
        'these relying parties.\n')
    alert_body += "\n".join([f'{x["name"]} : {x["client_id"]}' for x in clients])
    dedup_string = "\n".join(sorted([x["client_id"] for x in clients]))
    dedup_key = hashlib.sha256(dedup_string.encode('utf-8')).hexdigest()

    payload = {
        "routing_key": pagerduty_integration_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": "New Auth0 client(s)/app(s) created but missing "
                       "authorization configuration",
            "source": source,
            "severity": "error",
            "custom_details": {
                "alert_body": alert_body,
            },
        },
    }
    r = requests.post(
        'https://events.pagerduty.com/v2/enqueue',
        json=payload
    )
    print(f'Alerting to PagerDuty. Response : {r.status_code} : {r.text}')


def main(source: str):
    """Check for Auth0 clients that are missing apps.yml authorization configs

    Fetch the apps.yml authorization file as well as all Auth0 clients. Look
    for clients that are missing from apps.yml and send a Pagerduty alert on
    them.

    :param str source: The source of any alerts. This will help those receiving
        the alert to determine where it came from.
    :return:
    """
    # Note : Auth0 management API Key must be granted "read:clients" in Auth0
    # for the "Auth0 Management API" https://auth.mozilla.auth0.com/api/v2/
    client = boto3.client('ssm')
    response = client.get_parameter(
        Name='/iam/check_auth0_applications_missing_authorization/production/auth0_management_api_client_id')
    auth0_management_api_client_id = response['Parameter']['Value']
    response = client.get_parameter(
        Name='/iam/check_auth0_applications_missing_authorization/production/auth0_management_api_client_secret',
        WithDecryption=True
    )
    auth0_management_api_client_secret = response['Parameter']['Value']
    response = client.get_parameter(
        Name='/iam/check_auth0_applications_missing_authorization/production/pagerduty_integration_key',
        WithDecryption=True
    )
    pagerduty_integration_key = response['Parameter']['Value']
    temp_client_id_ignore_list = get_temp_client_id_ignore_list()

    r = requests.post(
        f'https://{AUTH0_AUDIENCE}/oauth/token',
        json={
            'client_id': auth0_management_api_client_id,
            'client_secret': auth0_management_api_client_secret,
            'audience': f'https://{AUTH0_AUDIENCE}/api/v2/',
            'grant_type': 'client_credentials'
        }
    )
    auth0_management_bearer_token = r.json()['access_token']

    r = requests.get('https://cdn.sso.mozilla.com/apps.yml')
    mozilla_authorization_data = yaml.load(r.text, Loader=yaml.SafeLoader)
    clients_with_authorization = [
        x['application']['client_id'] for x
        in mozilla_authorization_data['apps']
        if 'client_id' in x['application']]

    r = requests.get(
        f'https://{AUTH0_AUDIENCE}/api/v2/clients',
        headers={'Authorization': f'Bearer {auth0_management_bearer_token}'},
        params={
            'fields': 'client_id,name,app_type,callbacks',
            'app_type': 'regular_web,spa'
        })
    auth0_data = r.json()
    clients_missing_authorization = []
    for auth0_client in auth0_data:
        if (auth0_client['client_id'] not in temp_client_id_ignore_list
                and len(auth0_client['callbacks']) > 0
                and auth0_client['client_id'] not in clients_with_authorization):
            clients_missing_authorization.append(auth0_client)

    if clients_missing_authorization:
        alert(source, pagerduty_integration_key, clients_missing_authorization)

    sorted_clients = sorted(
        clients_missing_authorization, key=lambda x: x['name'])
    for auth0_client in sorted_clients:
        print(f'{auth0_client["name"]}  : {auth0_client["client_id"]} : '
              f'{auth0_client["app_type"]} : '
              f'{",".join(auth0_client["callbacks"])}"')


def lambda_handler(event, context):
    main(context.invoked_function_arn)


if __name__ == "__main__":
    main(socket.gethostname())