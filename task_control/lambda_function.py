import re
import os
import json
import execute
import interact


def format_response(status_code, result, message, log, **kwargs):
    response = {'result': result, 'message': message}
    if kwargs:
        for k, v in kwargs.items():
            response[k] = v
    if log:
        log['response'] = response
        print(log)
    return {'statusCode': status_code, 'body': json.dumps(response)}


def lambda_handler(event, context):
    region = re.search('arn:aws:lambda:([^:]+):.*', context.invoked_function_arn).group(1)
    campaign_id = os.environ['CAMPAIGN_ID']
    subnet = os.environ['subnet']
    log = {'event': event}

    user_id = event['requestContext']['authorizer']['user_id']
    data = event['body']

    if 'action' not in data:
        return format_response(400, 'failed', 'request must contain valid action', log)
    action = data['action']

    if 'detail' not in data:
        return format_response(400, 'failed', 'request must contain valid detail', log)
    detail = data['detail']

    if 'task_name' not in detail:
        return format_response(400, 'failed', 'request detail must contain task_id', log)
    task_name = detail['task_name']

    if action == 'execute':
        # Execute container task
        new_task = execute.Task(campaign_id, task_name, subnet, region, detail, user_id, log)
        response = new_task.run_task()
        return response

    if action == 'interact':
        # Send instructions to existing container task
        interact_task = interact.Task(campaign_id, task_name, region, detail, user_id, log)
        response = interact_task.instruct()
        return response