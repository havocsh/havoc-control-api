import os
import re
from authorizer import Login


def lambda_handler(event, context):
    region = re.search('arn:aws:lambda:([^:]+):.*', context.invoked_function_arn).group(1)
    campaign_id = os.environ['CAMPAIGN_ID']
    api_domain_name = os.environ['API_DOMAIN_NAME']
    if not api_domain_name:
        api_domain_name = f'{event["apiId"]}.execute-api.{region}.amazonaws.com'

    auth = Login(region, campaign_id, api_domain_name, event)
    auth.authorize_keys()
    response = auth.gen_response()

    return response
