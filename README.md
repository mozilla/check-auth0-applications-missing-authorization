# check-auth0-applications-missing-authorization

This is an AWS Lambda tool that runs daily to detect Auth0 clients that
were created but are mistakenly missing authorization information in [`apps.yml`](https://github.com/mozilla-iam/sso-dashboard-configuration/blob/master/apps.yml) 

If any misconfigured clients are found, the tool sends a Pagerduty alert.

# Deployment

Authenticate to AWS on the command line. For Mozilla's deployment this can be
done with [`maws`](https://github.com/mozilla-iam/mozilla-aws-cli).

Run `make deploy` which will spawn the `deploy.sh` script and pass it the
arguments for Mozilla's deployment of the tool. This script will deploy a
CloudFormation stack which provisions the AWS Lambda function, the AWS
EventBridge (CloudWatch Events) Rule to trigger the function every day at noon 
pacific time, as well as the required IAM Role and permissions to enable
EventBridge to invoke the function and for the function to read configuration
parameters from AWS SSM ParameterStore.

To update the already deployed tool if you make code changes, just run
`make deploy` which will update the already deployed CloudFormation stack.

# Configuration

The tool is hard coded to 

* use the production Mozilla Auth0 tenant (`auth.mozilla.auth0.com`)
* trigger every day at noon pacific time
* compare against the Mozilla deployed `apps.yml` file at https://cdn.sso.mozilla.com/apps.yml
* only consider specific clients/applications in Auth0 that meet these 
  requirements
  * are regular web applications or single page applications in Auth0
    (ignoring machine to machine and native integrations)
  * have at least one callback/redirect_uri configured (if no callback is
    configured, then no logins would work and so it can be ignored)
  * are not present in the `temp_client_id_ignore_list` configuration values
    which list out existing clients which are missing authorization.

The following settings can be configured in AWS SSM ParameterStore. The Mozilla
deployment of the tool runs in the `mozilla-iam` AWS account in `us-west-2`
which is where these configuration parameters can be found.

* `/iam/check_auth0_applications_missing_authorization/production/auth0_management_api_client_id`
  * The Auth0 client ID for the `Management API - check_auth0_applications_missing_authorization`
    Auth0 client which is used to query the [Auth0 management API](https://auth0.com/docs/api/management/v2#!/Clients/get_clients)
    for the list of clients/applications.
* `/iam/check_auth0_applications_missing_authorization/production/auth0_management_api_client_secret`
  * The Auth0 client secret for the `Management API - check_auth0_applications_missing_authorization`
    Auth0 client.
* `/iam/check_auth0_applications_missing_authorization/production/pagerduty_integration_key`
  * The PagerDuty API Key for the [PagerDuty Events API v2](https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTgw-events-api-v2-overview)
    which the tool uses to alert when it discovers Auth0 clients/applications
    that are missing an authorization entry in `apps.yml`
* `/iam/check_auth0_applications_missing_authorization/production/temp_client_id_ignore_list/*`
  * A collection of parameters (e.g. `/iam/check_auth0_applications_missing_authorization/production/temp_client_id_ignore_list/1`)
    which contain a comma delimted list of Auth0 client IDs to ignore. These are
    existing Auth0 clients/applications that are missing authorization entries
    in `apps.yml`. Once these clients are all addressed and added into 
    `apps.yml` the `temp_client_id_ignore_list` parameters can be deleted.

# Current PagerDuty Service

[IAM Relying Party Check](https://mozilla.pagerduty.com/service-directory/P2DSVSF)

# PagerDuty Alert

Each pagerduty alert has a deduplication key made up of a hash of the sorted
client IDs of the discovered misconfigured clients/applications.

Once the problem is fixed by adding authorization entries to `apps.yml`, the
PagerDuty alert will need to be manually resolved in PagerDuty by the PagerDuty
responder as it can't automatically be cleared.

## Example PagerDuty alert

* Title 
  * New Auth0 client(s)/app(s) created but missing authorization configuration
* Body 
  * The following new Auth0 client(s)/app(s) have been found but are missing 
    from "apps.yml" authorization configuration. Entries must be created in 
    "apps.yml" to assert what groups should have access to these relying 
    parties.
  * Example RP : abcdefghijklmnopqrstuvwxyz012345

# Logs

Logs of the most recent daily run of the tool can be found in an AWS CloudWatch
LogGroup with a name beginning with `/aws/lambda/CheckAuth0Apps-LambdaFunction-`
