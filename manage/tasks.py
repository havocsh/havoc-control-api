import json
import boto3


def format_response(status_code, result, message, log, **kwargs):
    response = {'result': result, 'message': message}
    if kwargs:
        for k, v in kwargs.items():
            response[k] = v
    if log:
        log['response'] = response
        print(log)
    return {'statusCode': status_code, 'body': json.dumps(response)}


class Tasks:

    def __init__(self, campaign_id, region, user_id, detail: dict, log):
        self.campaign_id = campaign_id
        self.region = region
        self.user_id = user_id
        self.detail = detail
        self.log = log
        self.task_name = None
        self.__aws_dynamodb_client = None
        self.__aws_ecs_client = None
        self.__aws_ec2_client = None

    @property
    def aws_dynamodb_client(self):
        """Returns the boto3 DynamoDB session (establishes one automatically if one does not already exist)"""
        if self.__aws_dynamodb_client is None:
            self.__aws_dynamodb_client = boto3.client('dynamodb', region_name=self.region)
        return self.__aws_dynamodb_client

    @property
    def aws_ecs_client(self):
        """Returns the boto3 ECS session (establishes one automatically if one does not already exist)"""
        if self.__aws_ecs_client is None:
            self.__aws_ecs_client = boto3.client('ecs', region_name=self.region)
        return self.__aws_ecs_client

    @property
    def aws_ec2_client(self):
        """Returns the boto3 EC2 session (establishes one automatically if one does not already exist)"""
        if self.__aws_ec2_client is None:
            self.__aws_ec2_client = boto3.client('ec2', region_name=self.region)
        return self.__aws_ec2_client

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

    def query_tasks(self):
        return self.aws_dynamodb_client.query(
            TableName=f'{self.campaign_id}_tasks',
        )

    def get_task_entry(self):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}_tasks',
            Key={
                'task_name': {'S': self.task_name}
            }
        )

    def delete_task_entry(self):
        response = self.aws_dynamodb_client.delete_item(
            TableName=f'{self.campaign_id}_tasks',
            Key={
                'task_name': {'S': self.task_name}
            }
        )
        assert response, f"delete_task_entry failed for task_name {self.task_name}"
        return True

    def update_task_entry(self, portgroups):
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}_tasks',
            Key={
                'task_name': {'S': self.task_name}
            },
            UpdateExpression='set portgroups=:portgroups',
            ExpressionAttributeValues={
                ':portgroups': {'SS': portgroups}
            }
        )
        assert response, f"add_task_entry failed for task_name {self.task_name}"
        return True

    def stop_ecs_task(self, ecs_task_id):
        response = self.aws_ecs_client.stop_task(
            cluster=f'{self.campaign_id}_cluster',
            task=ecs_task_id,
            reason=f'Task stopped by {self.user_id}'
        )
        assert response, f"stop_ecs_task failed for task_name {self.task_name}, ecs_task_id {ecs_task_id}"
        return True

    def kill(self):
        if 'task_name' not in self.detail:
            return format_response(400, 'failed', 'invalid detail', self.log)
        self.task_name = self.detail['task_name']

        task_entry = self.get_task_entry()
        if 'Item' not in task_entry:
            return format_response(400, 'failed', f'task {self.task_name} does not exist', self.log)

        ecs_task_id = task_entry['Item']['ecs_task_id']['S']
        if ecs_task_id == 'remote_task':
            return format_response(400, 'failed', f'task {self.task_name} is a remote task', self.log)

        portgroups = task_entry['Item']['portgroups']['SS']
        for portgroup in portgroups:
            if portgroup != 'None':
                portgroup_entry = self.get_portgroup_entry(portgroup)
                tasks = portgroup_entry['Item']['tasks']['SS']
                tasks.remove(self.task_name)
                if not tasks:
                    tasks.append('None')
                self.update_portgroup_entry(portgroup, tasks)
        self.stop_ecs_task(ecs_task_id)
        self.delete_task_entry()
        return format_response(200, 'success', 'kill task succeeded', None)

    def list(self):

        tasks_list = []

        tasks = self.query_tasks()
        for item in tasks['Items']:
            task_name = item['task_name']['S']
            task_type = item['task_type']['S']
            task_context = item['task_context']['S']
            task_status = item['task_status']['S']
            attack_ip = item['attack_ip']['M']
            attack_ip_fixup = {}
            for key, value in attack_ip.items():
                attack_ip_fixup[key] = value['S']
            portgroups = item['portgroups']['SS']
            instruct_instances = item['instruct_instances']['SS']
            last_instruct_user_id = item['last_instruct_user_id']['S']
            last_instruct_instance = item['last_instruct_instance']['S']
            last_instruct_command = item['last_instruct_command']['S']
            last_instruct_args = item['last_instruct_args']['M']
            last_instruct_args_fixup = {}
            for key, value in last_instruct_args.items():
                if 'S' in value:
                    last_instruct_args_fixup[key] = value['S']
                if 'N' in value:
                    last_instruct_args_fixup[key] = value['N']
                if 'B' in value:
                    last_instruct_args_fixup[key] = value['B']
            last_instruct_time = item['last_instruct_time']['S']
            task_creator_user_id = item['user_id']['S']
            create_time = item['create_time']['S']
            scheduled_end_time = item['scheduled_end_time']['S']
            ecs_task_id = item['ecs_task_id']
            tasks_list.append({'task_name': task_name, 'task_type': task_type, 'task_context': task_context,
                               'task_status': task_status, 'attack_ip': attack_ip_fixup, 'portgroups': portgroups,
                               'instruct_instances': instruct_instances, 'last_instruct_user_id': last_instruct_user_id,
                               'last_instruct_instance': last_instruct_instance,
                               'last_instruct_command': last_instruct_command,
                               'last_instruct_args': last_instruct_args_fixup, 'last_instruct_time': last_instruct_time,
                               'task_creator_user_id': task_creator_user_id, 'create_time': create_time,
                               'scheduled_end_time': scheduled_end_time, 'ecs_task_id': ecs_task_id})
        return format_response(200, 'success', 'list tasks succeeded', None, tasks=tasks_list)

    def create(self):
        return format_response(400, 'failed', 'invalid request', self.log)

    def delete(self):
        return format_response(400, 'failed', 'invalid request', self.log)

    def get(self):
        return format_response(400, 'failed', 'invalid request', self.log)

    def update(self):
        return format_response(400, 'failed', 'invalid request', self.log)
