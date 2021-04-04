import re
from authorizer import Login


def lambda_handler(event, context):
    region = re.search('arn:aws:lambda:([^:]+):.*', context.invoked_function_arn).group(1)
    print('event:' + event)
    print('context:' + context)

    auth = Login(region, event)
    auth.authorize_keys()
    response = auth.gen_response()

    return response
