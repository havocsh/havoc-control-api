import os
import re
import json
import base64
import zlib
from deliver import Deliver


def lambda_handler(event, context):
    region = re.search('arn:aws:lambda:([^:]+):.*', context.invoked_function_arn).group(1)
    campaign_id = os.environ['CAMPAIGN_ID']
    zipped = base64.b64decode(event['awslogs']['data'])
    raw = zlib.decompress(zipped, 15 + 32)
    data = json.loads(raw.decode('utf-8'))
    log_events = data['logEvents']

    d = Deliver(region, campaign_id, log_events)
    d.deliver_result()
