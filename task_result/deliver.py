import re
import ast
import json
import copy
import boto3
from datetime import datetime, timezone


class Deliver:
    def __init__(self, region, campaign_id, websocket_url, log_events):
        self.region = region
        self.campaign_id = campaign_id
        self.websocket_url = websocket_url
        self.log_events = log_events
        self.user_id = None
        self.connection_id = None
        self.__connection = None
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

    @property
    def aws_apigw_client(self):
        """Returns the APIGatewayManagement boto3 session (establishes one automatically if one does not already exist)"""
        if self.__aws_apigw_client is None:
            self.__aws_apigw_client = boto3.client('apigatewaymanagementapi',
                              endpoint_url=self.websocket_url)
        return self.__aws_apigw_client

    @property
    def connection(self):
        if self.__connection is None:
            try:
                self.__connection = self.aws_apigw_client.get_connection(
                    ConnectionId=self.connection_id
                )
            except:
                self.__connection = False
            return self.__connection

    def upload_object(self, payload_bytes, stime):
        response = self.aws_s3_client.put_object(
            Body=payload_bytes,
            Bucket=f'{self.campaign_id}-logging',
            Key=stime + '.txt'
        )
        assert response, 'upload_object failed'

    def add_queue_attribute(self, stime, task_name, task_context, task_type, task_instruct_instance,
                            task_instruct_command, task_instruct_args, task_attack_ip, json_payload):
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}_queue',
            Key={
                'run_time': {'N': stime}
            },
            UpdateExpression='set user_id=:user_id, task_name=:task_name, task_context=:task_context, '
                             'task_type=:task_type, instruct_instance=:instruct_instance, '
                             'instruct_command=:instruct_command, instruct_args=:instruct_args, attack_ip=:attack_ip, '
                             'task_result=:payload',
            ExpressionAttributeValues={
                ':user_id': {'S': self.user_id},
                ':task_name': {'S': task_name},
                ':task_context': {'S': task_context},
                ':task_type': {'S': task_type},
                ':instruct_instance': {'S': task_instruct_instance},
                ':instruct_command': {'S': task_instruct_command},
                ':instruct_args': {'M': task_instruct_args},
                ':attack_ip': {'S': task_attack_ip},
                ':payload': {'S': json_payload}
            }
        )
        assert response, f'add_queue_attribute failed for task_name {task_name}'

    def post_message(self, json_results):
        response = self.aws_apigw_client.post_to_connection(
            Data=json_results,
            ConnectionId=self.connection_id
        )
        assert response, f'post_message failed for connection_id {self.connection_id}'

    def get_task_entry(self, task_name):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}_tasks',
            Key={
                'task_name': {'S': task_name}
            }
        )

    def update_task_entry(self, stime, task_name, task_status, task_end_time):
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}_tasks',
            Key={
                'task_name': {'S': task_name}
            },
            UpdateExpression='set task_status=:task_status, last_instruct_time=:last_instruct_time, '
                             'scheduled_end_time=:scheduled_end_time',
            ExpressionAttributeValues={
                ':task_status': {'S': task_status},
                ':last_instruct_time': {'S': stime},
                ':scheduled_end_time': {'S': task_end_time}
            }
        )
        assert response, f"update_task_entry failed for task_name {task_name}"
        return True

    def delete_task_entry(self, task_name):
        response = self.aws_dynamodb_client.delete_item(
            TableName=f'{self.campaign_id}_tasks',
            Key={
                'task_name': {'S': task_name}
            }
        )
        assert response, f"delete_task_entry failed for task_name {task_name}"
        return True

    def get_portgroup_entry(self, portgroup_name):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}_portgroups',
            Key={
                'portgroup_name': {'S': portgroup_name}
            }
        )

    def update_portgroup_entry(self, portgroup_name, portgroup_tasks):
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}_portgroups',
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
        timestamp = str(self.log_events[0]['timestamp'])
        stime = datetime.now(timezone.utc).strftime('%s')

        payload = None
        try:
            payload = json.loads(self.log_events[0]['message'])
        except:
            pass
        if not payload:
            raw = re.search('\d+-\d+-\d+ \d+:\d+:\d+\+\d+ \[-\] ({.+})', self.log_events[0]['message']).group(1)
            payload = ast.literal_eval(raw)

        if payload['instruct_user'] == 'None':
            self.user_id = payload['user_id']
        else:
            self.user_id = payload['instruct_user']
        task_name = payload['task_name']
        task_context = payload['task_context']
        task_type = payload['task_type']
        task_interactive = payload['interactive']
        task_instruct_instance = payload['instruct_instance']
        task_instruct_command = payload['instruct_command']
        task_instruct_args = payload['instruct_args']
        task_attack_ip = payload['attack_ip']
        task_forward_log = payload['forward_log']
        self.connection_id = payload['connection_id']
        if 'end_time' in payload:
            task_end_time = payload['end_time']
        else:
            task_end_time = 'None'

        # Add timestamp to payload
        payload['timestamp'] = timestamp

        # Get task portgroups
        task_entry = self.get_task_entry(task_name)
        portgroups = task_entry['Item']['portgroups']['SS']

        # Clear out unwanted payload entries
        del payload['instruct_user']
        del payload['end_time']
        del payload['interactive']
        del payload['connection_id']
        del payload['forward_log']

        # Send response if task_interactive is True and client is still connected.
        if task_interactive == 'True':
            if self.connection:
                if 'status' in payload['task_response']:
                    if payload['task_response']['status'] == 'ready' or payload['task_response']['status'] == 'terminating':
                        payload['portgroups'] = portgroups
                response = {'statusCode': 200, 'body': payload}
                self.post_message(json.dumps(response))

        if task_forward_log == 'True':
            s3_payload = copy.deepcopy(payload)
            if task_instruct_command == 'terminate':
                del s3_payload['instruct_args']
            if 'status' in s3_payload['task_response']:
                if s3_payload['task_response']['status'] == 'ready':
                    del s3_payload['instruct_args']

            # Send result to S3
            payload_bytes = json.dumps(s3_payload).encode('utf-8')
            self.upload_object(payload_bytes, stime)

        # Add job to results queue
        db_payload = copy.deepcopy(payload)
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
            self.add_queue_attribute(stime, task_name, task_context, task_type, task_instruct_instance,
                                     task_instruct_command, task_instruct_args_fixup, task_attack_ip, json_payload)
        if task_instruct_command == 'terminate':
            for portgroup in portgroups:
                if portgroup != 'None':
                    portgroup_entry = self.get_portgroup_entry(portgroup)
                    tasks = portgroup_entry['Item']['tasks']['SS']
                    tasks.remove(task_name)
                    if not tasks:
                        tasks.append('None')
                    self.update_portgroup_entry(portgroup, tasks)
            self.delete_task_entry(task_name)
        else:
            self.update_task_entry(stime, task_name, 'idle', task_end_time)

        return True