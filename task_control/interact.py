import json
import boto3

from datetime import datetime


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


class Task:

    def __init__(self, campaign_id, task_name, region, detail: dict, user_id, log):
        self.campaign_id = campaign_id
        self.task_name = task_name
        self.region = region
        self.detail = detail
        self.user_id = user_id
        self.log = log
        self.__aws_dynamodb_client = None
        self.__aws_s3_client = None

    @property
    def aws_dynamodb_client(self):
        """Returns the boto3 DynamoDB session (establishes one automatically if one does not already exist)"""
        if self.__aws_dynamodb_client is None:
            self.__aws_dynamodb_client = boto3.client('dynamodb', region_name=self.region)
        return self.__aws_dynamodb_client

    @property
    def aws_s3_client(self):
        """Returns the boto3 S3 session (establishes one automatically if one does not already exist)"""
        if self.__aws_s3_client is None:
            self.__aws_s3_client = boto3.client('s3', region_name=self.region)
        return self.__aws_s3_client

    def get_task_entry(self):
        response = self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-tasks',
            Key={
                'task_name': {'S': self.task_name}
            }
        )
        assert response, f"get_task_entry failed for task_name {self.task_name}"
        return response

    def get_task_type(self, task_type):
        response = self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-task-types',
            Key={
                'task_type': {'S': task_type}
            }
        )
        assert response, f"get_task_type failed for task_type {task_type}"
        return response

    def set_task_busy(self, instruct_instances, instruct_instance, instruct_command, instruct_args, timestamp):
        task_status = 'busy'
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}-tasks',
            Key={
                'task_name': {'S': self.task_name}
            },
            UpdateExpression='set task_status=:task_status, instruct_instances=:instruct_instances, '
                             'last_instruct_user_id=:last_instruct_user_id, '
                             'last_instruct_instance=:last_instruct_instance, '
                             'last_instruct_command=:last_instruct_command, last_instruct_args=:last_instruct_args, '
                             'last_instruct_time=:last_instruct_time',
            ExpressionAttributeValues={
                ':task_status': {'S': task_status},
                ':instruct_instances': {'SS': instruct_instances},
                ':last_instruct_user_id': {'S': self.user_id},
                ':last_instruct_instance': {'S': instruct_instance},
                ':last_instruct_command': {'S': instruct_command},
                ':last_instruct_args': {'M': instruct_args},
                ':last_instruct_time': {'S': timestamp}
            }
        )
        assert response, f"add_task_entry failed for task_name {self.task_name}"
        return True

    def upload_object(self, instruct_instance, instruct_command, instruct_args, end_time, timestamp):
        payload = {
            'instruct_user_id': self.user_id, 'instruct_instance': instruct_instance,
            'instruct_command': instruct_command, 'instruct_args': instruct_args, 'timestamp': timestamp,
            'end_time': end_time
        }
        payload_bytes = json.dumps(payload).encode('utf-8')
        response = self.aws_s3_client.put_object(
            Body=payload_bytes,
            Bucket=f'{self.campaign_id}-workspace',
            Key=self.task_name + '/' + timestamp
        )
        assert response, f"Failed to upload object to workspace for task_name {self.task_name}"
        return True

    def instruct(self):
        timestamp = datetime.now().strftime('%s')
        try:
            instruct_command = self.detail['instruct_command']
        except:
            return format_response(400, 'failed', 'missing instruct_command', self.log)

        if 'instruct_instance' in self.detail and self.detail['instruct_instance']:
            instruct_instance = self.detail['instruct_instance']
        else:
            instruct_instance = 'havoc'
        if 'instruct_args' in self.detail and self.detail['instruct_args']:
            instruct_args = self.detail['instruct_args']
        else:
            instruct_args = {'no_args': 'True'}
        if 'end_time' in self.detail and self.detail['end_time']:
            end_time = self.detail['end_time']
        else:
            end_time = 'None'

        # Validate that task exists and error if it does not
        task_entry = self.get_task_entry()
        if 'Item' not in task_entry:
            return format_response(404, 'failed', f'task_name {self.task_name} not found', self.log)

        # Get task capabilities from the task and validate instruct_command
        task_type = task_entry['Item']['task_type']['S']
        task_type_details = self.get_task_type(task_type)
        capabilities = task_type_details['Item']['capabilities']['SS']
        if instruct_command not in capabilities:
            return format_response(400, 'failed', f'{instruct_command} not valid for task_name {self.task_name}',
                                   self.log)

        # Validate that task is idle
        if task_entry['Item']['task_status']['S'] == 'starting':
            return format_response(409, 'failed', f'task {self.task_name} is still starting', self.log)
        if task_entry['Item']['task_status']['S'] == 'busy':
            return format_response(409, 'failed', f'task {self.task_name} is busy', self.log)
        if task_entry['Item']['task_status']['S'] == 'finished':
            return format_response(409, 'failed', f'task {self.task_name} no longer running', self.log)

        # Add new instruct_instance to instruct_instances list
        instruct_instances = task_entry['Item']['instruct_instances']['SS']
        if instruct_instances[0] == 'None':
            instruct_instances.clear()
        if instruct_instance not in instruct_instances:
            instruct_instances.append(instruct_instance)

        # Convert instruct_args to DynamoDB map format
        instruct_args_fixup = {}
        for k, v in instruct_args.items():
            if isinstance(v, str):
                instruct_args_fixup[k] = {'S': f'{v}'}
            if isinstance(v, int) and not isinstance(v, bool):
                instruct_args_fixup[k] = {'N': f'{v}'}
            if isinstance(v, bool):
                instruct_args_fixup[k] = {'BOOL': v}
            if isinstance(v, bytes):
                instruct_args_fixup[k] = {'B': f'{v}'}

        # Set task to busy and send instructions to the task
        self.set_task_busy(instruct_instances, instruct_instance, instruct_command, instruct_args_fixup, timestamp)
        self.upload_object(instruct_instance, instruct_command, instruct_args, end_time, timestamp)

        # Send response
        return format_response(200, 'success', f'interact with {self.task_name} succeeded', None)
