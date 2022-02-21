import os
import re
import json
import domains
import portgroups
import task_type
import tasks
import users
import workspace


def format_response(status_code, result, message, log, **kwargs):
    response = {'outcome': result}
    if message:
        response['message'] = message
    if kwargs:
        for k, v in kwargs.items():
            if v:
                response[k] = v
    if log:
        log['response'] = response
        print(log)
    return {'statusCode': status_code, 'body': json.dumps(response)}


def action(resource, command, region, campaign_id, user_id, detail, log):
    resources = {
        'domain': domains.Domain(campaign_id, region, user_id, detail, log),
        'portgroup': portgroups.Portgroup(campaign_id, region, user_id, detail, log),
        'task_type': task_type.Registration(campaign_id, region, user_id, detail, log),
        'task': tasks.Tasks(campaign_id, region, user_id, detail, log),
        'user': users.Users(campaign_id, region, user_id, detail, log),
        'workspace': workspace.Workspace(campaign_id, region, user_id, detail, log),
    }
    r = resources[resource]
    functions = {
        'create': r.create,
        'delete': r.delete,
        'get': r.get,
        'kill': r.kill,
        'list': r.list,
        'update': r.update
    }
    call_function = functions[command]()
    return call_function


def lambda_handler(event, context):
    region = re.search('arn:aws:lambda:([^:]+):.*', context.invoked_function_arn).group(1)
    user_id = event['requestContext']['authorizer']['user_id']
    campaign_id = os.environ['CAMPAIGN_ID']
    log = {'event': event}

    data = json.loads(event['body'])
    if 'command' not in data:
        return format_response(400, 'failed', 'missing command', log)
    command = data['command']

    allowed_commands = ['create', 'delete', 'get', 'kill', 'list', 'update']
    if command not in allowed_commands:
        return format_response(400, 'failed', 'invalid command', log)

    if 'resource' not in data:
        return format_response(400, 'failed', 'missing resource', log)
    resource = data['resource']

    allowed_resources = ['domain', 'portgroup', 'task_type', 'task', 'user', 'workspace']
    if resource not in allowed_resources:
        return format_response(400, 'failed', 'invalid resource', log)

    if 'detail' in data:
        detail = data['detail']
    else:
        detail = {}

    response = action(resource, command, region, campaign_id, user_id, detail, log)
    return response
