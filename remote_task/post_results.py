import json
import copy
import boto3
from datetime import datetime, timezone


def format_response(status_code, result, message, log, **kwargs):
    response = {'result': result}
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


class Deliver:

    def __init__(self, campaign_id, region, user_id, results: dict, log):
        self.campaign_id = campaign_id
        self.region = region
        self.user_id = user_id
        self.results = results
        self.log = log
        self.task_name = None
        self.task_context = None
        self.task_type = None
        self.__aws_s3_client = None
        self.__aws_dynamodb_client = None
        self.__aws_apigw_client = None

    @property
    def aws_s3_client(self):
        """Returns the boto3 S3 session (establishes one automatically if one does not already exist)"""
        if self.__aws_s3_client is None:
            self.__aws_s3_client = boto3.client('s3', region_name=self.region)
        return self.__aws_s3_client

    @property
    def aws_dynamodb_client(self):
        """Returns the Dynamodb boto3 session (establishes one automatically if one does not already exist)"""
        if self.__aws_dynamodb_client is None:
            self.__aws_dynamodb_client = boto3.client('dynamodb', region_name=self.region)
        return self.__aws_dynamodb_client

    def upload_object(self, payload_bytes, stime):
        response = self.aws_s3_client.put_object(
            Body=payload_bytes,
            Bucket=f'{self.campaign_id}-logging',
            Key=stime + '.txt'
        )
        assert response, 'upload_object failed'

    def add_queue_attribute(self, stime, task_instruct_instance, task_instruct_command, task_instruct_args,
                            task_attack_ip, json_payload):
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}-queue',
            Key={
                'run_time': {'N': stime}
            },
            UpdateExpression='user_id=:user_id, task_name=:task_name, task_context=:task_context, '
                             'task_type=:task_type, instruct_instance=:instruct_instance, '
                             'instruct_command=:instruct_command, instruct_args=:instruct_args, attack_ip=:attack_ip, '
                             'task_result=:payload',
            ExpressionAttributeValues={
                ':user_id': {'S': self.user_id},
                ':task_name': {'S': self.task_name},
                ':task_context': {'S': self.task_context},
                ':task_type': {'S': self.task_type},
                ':instruct_instance': {'S': task_instruct_instance},
                ':instruct_command': {'S': task_instruct_command},
                ':instruct_args': {'M': task_instruct_args},
                ':attack_ip': {'M': task_attack_ip},
                ':payload': {'S': json_payload}
            }
        )
        assert response, f'add_queue_attribute failed'
        return True

    def get_task_entry(self):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-tasks',
            Key={
                'task_name': {'S': self.task_name}
            }
        )

    def update_task_entry(self, stime, task_status, task_end_time):
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}-tasks',
            Key={
                'task_name': {'S': self.task_name}
            },
            UpdateExpression='set task_status=:task_status, last_instruct_time=:last_instruct_time, '
                             'scheduled_end_time=:scheduled_end_time',
            ExpressionAttributeValues={
                ':task_status': {'S': task_status},
                ':last_instruct_time': {'S': stime},
                ':scheduled_end_time': {'S': task_end_time}
            }
        )
        assert response, f"update_task_entry failed for task_name {self.task_name}"
        return True

    def delete_task_entry(self):
        response = self.aws_dynamodb_client.delete_item(
            TableName=f'{self.campaign_id}-tasks',
            Key={
                'task_name': {'S': self.task_name}
            }
        )
        assert response, f"delete_task_entry failed for task_name {self.task_name}"
        return True

    def get_portgroup_entry(self, portgroup_name):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-portgroups',
            Key={
                'portgroup_name': {'S': portgroup_name}
            }
        )

    def update_portgroup_entry(self, portgroup_name, portgroup_tasks):
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}-portgroups',
            Key={
                'portgroup_name': {'S': portgroup_name}
            },
            UpdateExpression='set tasks=:tasks',
            ExpressionAttributeValues={
                ':tasks': {'SS': portgroup_tasks}
            }
        )
        assert response, f"update_portgroup_entry failed for portgroup_name {portgroup_name}"
        return True

    def deliver_result(self):
        # Set vars
        stime = datetime.now(timezone.utc).strftime('%s')
        results_reqs = [
            'task_name', 'task_context', 'task_type', 'task_instruct_instance', 'task_instruct_command',
            'task_instruct_args', 'task_attack_ip', 'task_forward_log'
        ]
        for i in results_reqs:
            if i not in self.results:
                return format_response(400, 'failed', 'invalid results', self.log)

        self.task_name = self.results['task_name']
        self.task_context = self.results['task_context']
        self.task_type = self.results['task_type']
        task_instruct_instance = self.results['instruct_instance']
        task_instruct_command = self.results['instruct_command']
        task_instruct_args = self.results['instruct_args']
        task_attack_ip = self.results['attack_ip']
        task_forward_log = self.results['forward_log']

        if self.results['instruct_user'] != 'None':
            self.user_id = self.results['instruct_user']
        if 'end_time' in self.results:
            task_end_time = self.results['end_time']
        else:
            task_end_time = 'None'

        # Get task portgroups
        task_entry = self.get_task_entry()
        if 'Item' not in task_entry:
            return format_response(404, 'failed', f'task_name {self.task_name} not found', self.log)
        portgroups = task_entry['Item']['portgroups']['SS']

        # Clear out unwanted results entries
        del self.results['end_time']
        del self.results['forward_log']

        if task_forward_log == 'True':
            s3_payload = copy.deepcopy(self.results)
            if task_instruct_command == 'terminate':
                del s3_payload['instruct_args']
            if 'status' in s3_payload['task_response']:
                if s3_payload['task_response']['status'] == 'ready':
                    del s3_payload['instruct_args']

            # Send result to S3
            payload_bytes = json.dumps(s3_payload).encode('utf-8')
            self.upload_object(payload_bytes, stime)

        # Add job to results queue
        db_payload = copy.deepcopy(self.results)
        del db_payload['task_name']
        del db_payload['task_type']
        del db_payload['instruct_instance']
        del db_payload['instruct_command']
        del db_payload['instruct_args']
        del db_payload['attack_ip']
        del db_payload['timestamp']
        json_payload = json.dumps(db_payload)
        if task_forward_log == 'True':
            task_instruct_args_fixup = {}
            for k, v in task_instruct_args.items():
                if isinstance(v, str):
                    task_instruct_args_fixup[k] = {'S': v}
                if isinstance(v, int):
                    task_instruct_args_fixup[k] = {'N': v}
                if isinstance(v, bytes):
                    task_instruct_args_fixup[k] = {'B': v}
            task_attack_ip_fixup = {}
            for key, value in task_attack_ip.items():
                task_attack_ip_fixup[key] = {'S': value}
            self.add_queue_attribute(stime, task_instruct_instance, task_instruct_command, task_instruct_args_fixup,
                                     task_attack_ip_fixup, json_payload)
        if task_instruct_command == 'terminate':
            for portgroup in portgroups:
                if portgroup != 'None':
                    portgroup_entry = self.get_portgroup_entry(portgroup)
                    tasks = portgroup_entry['Item']['tasks']['SS']
                    tasks.remove(self.task_name)
                    if not tasks:
                        tasks.append('None')
                    self.update_portgroup_entry(portgroup, tasks)
            self.delete_task_entry()
        else:
            self.update_task_entry(stime, 'idle', task_end_time)

        response = {'result': 'success'}
        return {'statusCode': 200, 'body': json.dumps(response)}
