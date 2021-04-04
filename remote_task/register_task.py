import json
import boto3
from datetime import datetime


def format_response(status_code, result, message, log, **kwargs):
    response = {'result': result, 'message': message}
    if kwargs:
        for k, v in kwargs.items():
            response[k] = v
    if log:
        log['response'] = response
        print(log)
    return {'statusCode': status_code, 'body': json.dumps(response)}


class Task():
    def __init__(self, campaign_id, region, user_id, detail: dict, log):
        """
        Register a remote task instance
        """
        self.campaign_id = campaign_id
        self.region = region
        self.detail = detail
        self.user_id = user_id
        self.log = log
        self.task_name = None
        self.task_context = None
        self.task_type = None
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

    def get_task_type_entry(self):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}_task_types',
            Key={
                'task_type': {'S': self.task_type}
            }
        )

    def get_task_entry(self):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}_tasks',
            Key={
                'task_name': {'S': self.task_name}
            }
        )

    def upload_object(self, instruct_user_id, instruct_instance, instruct_command, instruct_args, end_time):
        if end_time == 'None':
            payload = {'connection_id': None, 'interactive': 'False', 'task_name': self.task_name,
                       'task_context': self.task_context, 'task_type': self.task_type,
                       'instruct_user_id': instruct_user_id, 'instruct_instance': instruct_instance,
                       'instruct_command': instruct_command, 'instruct_args': instruct_args}
        else:
            payload = {'connection_id': None, 'interactive': 'False',  'task_name': self.task_name,
                       'task_context': self.task_context,'task_type': self.task_type,
                       'instruct_user_id': instruct_user_id, 'instruct_instance': instruct_instance,
                       'instruct_command': instruct_command, 'instruct_args': instruct_args, 'end_time': end_time}
        payload_bytes = json.dumps(payload).encode('utf-8')
        response = self.aws_s3_client.put_object(
            Body=payload_bytes,
            Bucket=f'{self.campaign_id}-workspace',
            Key=self.task_name + '/init.txt'
        )
        assert response, f"Failed to initialize workspace for task_name {self.task_name}"
        return True

    def add_task_entry(self, instruct_user_id, instruct_instance, instruct_command, instruct_args, attack_ip,
                       portgroups, ecs_task_id, timestamp, end_time):
        task_status = 'starting'
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}_tasks',
            Key={
                'task_name': {'S': self.task_name}
            },
            UpdateExpression='set task_context=:task_context, task_status=:task_status, attack_ip=:attack_ip, '
                             'portgroups=:portgroups, task_type=:task_type, instruct_instances=:instruct_instances, '
                             'last_instruct_user_id=:last_instruct_user_id, '
                             'last_instruct_instance=:last_instruct_instance, '
                             'last_instruct_command=:last_instruct_command, last_instruct_args=:last_instruct_args, '
                             'last_instruct_time=:last_instruct_time, create_time=:create_time, '
                             'scheduled_end_time=:scheduled_end_time, user_id=:user_id, ecs_task_id=:ecs_task_id',
            ExpressionAttributeValues={
                ':task_context': {'S': self.task_context},
                ':task_status': {'S': task_status},
                ':attack_ip': {'M': attack_ip},
                ':portgroups': {'SS': portgroups},
                ':task_type': {'S': self.task_type},
                ':instruct_instances': {'SS': [instruct_instance]},
                ':last_instruct_user_id': {'S': instruct_user_id},
                ':last_instruct_instance': {'S': instruct_instance},
                ':last_instruct_command': {'S': instruct_command},
                ':last_instruct_args': {'M': instruct_args},
                ':last_instruct_time': {'S': 'None'},
                ':create_time': {'S': timestamp},
                ':scheduled_end_time': {'S': end_time},
                ':user_id': {'S': self.user_id},
                ':ecs_task_id': {'S': ecs_task_id}
            }
        )
        assert response, f"add_task_entry failed for task {self.task_name}"
        return True

    def registration(self):
        portgroups = ['None']
        ecs_task_id = 'remote_task'
        instruct_user_id = 'None'
        instruct_instance = 'None'
        instruct_command = 'init'
        instruct_args = {'no_args': 'True'}
        if 'end_time' in self.detail:
            end_time = self.detail['end_time']
        else:
            end_time = 'None'

        instruct_details = ['task_name', 'task_context', 'task_type', 'attack_ip']
        for i in instruct_details:
            if i not in self.detail:
                return format_response(400, 'failed', 'invalid detail', self.log)

        self.task_name = self.detail['task_name']
        self.task_context = self.detail['task_context']
        self.task_type = self.detail['task_type']
        attack_ip = self.detail['attack_ip']

        task_type_entry = self.get_task_type_entry()
        if 'Item' not in task_type_entry:
            return format_response(400, 'failed', f'task_type {self.task_type} does not exist', self.log)

        # Verify that the task_name is unique
        conflict = self.get_task_entry()
        if 'Item' in conflict:
            return format_response(409, 'failed', f'{self.task_name} already exists', self.log)

        recorded_info = {
            'task_registered': {
                'user_id': self.user_id, 'task_name': self.task_name,
                'task_context': self.task_context, 'task_type': self.task_type,
                'interface_details': attack_ip
            }
        }
        print(recorded_info)

        timestamp = datetime.now().strftime('%s')
        self.upload_object(instruct_user_id, instruct_instance, instruct_command, instruct_args, end_time)

        # Convert attack_ip for inclusion in task entry
        attack_ip_fixup = {}
        for key, value in attack_ip.items():
            attack_ip_fixup[key] = {'S': value}
        instruct_args_fixup = {'no_args': {'S': 'True'}}
        # Add task entry to tasks table in DynamoDB
        self.add_task_entry(instruct_user_id, instruct_instance, instruct_command, instruct_args_fixup,
                            attack_ip_fixup, portgroups, ecs_task_id, timestamp, end_time)

        # Send response
        return format_response(200, 'success', 'register task succeeded', None)