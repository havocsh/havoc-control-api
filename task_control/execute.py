import re
import json
import boto3
from datetime import datetime
import time as t


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

    def __init__(self, campaign_id, task_name, subnet, region, detail: dict, user_id, log):
        """
        Instantiate a Task instance
        """
        self.campaign_id = campaign_id
        self.task_name = task_name
        self.task_context = f'{self.campaign_id}-{region}'
        self.subnet = subnet
        self.region = region
        self.detail = detail
        self.user_id = user_id
        self.log = log
        self.task_type = None
        self.run_task_response = None
        self.__aws_dynamodb_client = None
        self.__aws_ecs_client = None
        self.__aws_ec2_client = None
        self.__aws_s3_client = None
        self.__aws_route53_client = None

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

    @property
    def aws_s3_client(self):
        """Returns the boto3 S3 session (establishes one automatically if one does not already exist)"""
        if self.__aws_s3_client is None:
            self.__aws_s3_client = boto3.client('s3', region_name=self.region)
        return self.__aws_s3_client

    @property
    def aws_route53_client(self):
        """Returns the boto3 Route53 session for this project (establishes one automatically if one does not already exist)"""
        if self.__aws_route53_client is None:
            self.__aws_route53_client = boto3.client('route53')
        return self.__aws_route53_client

    def get_domain_entry(self, domain_name):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-domains',
            Key={
                'domain_name': {'S': domain_name}
            }
        )

    def create_resource_record(self, hosted_zone, host_name, domain_name, ip_address):
        response = self.aws_route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet':{
                            'Name': f'{host_name}.{domain_name}',
                            'Type': 'A',
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': ip_address
                                }
                            ]
                        }
                    }
                ]
            }
        )
        if response:
            return True
        else:
            return False

    def update_domain_entry(self, domain_name, domain_tasks, host_names):
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}-domains',
            Key={
                'domain_name': {'S': domain_name}
            },
            UpdateExpression='set tasks=:tasks, host_names=:host_names',
            ExpressionAttributeValues={
                ':tasks': {'SS': domain_tasks},
                ':host_names': {'SS': host_names}
            }
        )
        assert response, f"update_domain_entry failed for domain_name {domain_name}"
        return True

    def get_task_type_entry(self):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-task-types',
            Key={
                'task_type': {'S': self.task_type}
            }
        )

    def get_task_entry(self):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-tasks',
            Key={
                'task_name': {'S': self.task_name}
            }
        )

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

    def upload_object(self, instruct_user_id, instruct_instance, instruct_command, instruct_args, timestamp, end_time):
        payload = {
            'instruct_user_id': instruct_user_id, 'instruct_instance': instruct_instance,
            'instruct_command': instruct_command, 'instruct_args': instruct_args, 'timestamp': timestamp,
            'end_time': end_time
        }
        payload_bytes = json.dumps(payload).encode('utf-8')
        response = self.aws_s3_client.put_object(
            Body=payload_bytes,
            Bucket=f'{self.campaign_id}-workspace',
            Key=self.task_name + '/init.txt'
        )
        assert response, f"Failed to initialize workspace for task_name {self.task_name}"
        return True

    def run_attack_task(self, securitygroups, end_time):
        response = self.aws_ecs_client.run_task(
            cluster=f'{self.campaign_id}-cluster',
            count=1,
            launchType='FARGATE',
            networkConfiguration={
                'awsvpcConfiguration': {
                    'subnets': [self.subnet],
                    'securityGroups': securitygroups,
                    'assignPublicIp': 'ENABLED'
                }
            },
            overrides={
                'containerOverrides': [
                    {
                        'name': f'{self.campaign_id}-{self.task_type}',
                        'environment': [
                            {'name': 'REGION', 'value': self.region},
                            {'name': 'CAMPAIGN_ID', 'value': self.campaign_id},
                            {'name': 'USER_ID', 'value': self.user_id},
                            {'name': 'TASK_NAME', 'value': self.task_name},
                            {'name': 'TASK_CONTEXT', 'value': self.task_context},
                            {'name': 'END_TIME', 'value': end_time}
                        ]
                    }
                ]
            },
            tags=[
                {
                    'key': 'task_name',
                    'value': self.task_name
                }
            ],
            taskDefinition=self.task_type
        )
        self.run_task_response = response

    def get_ecstask_details(self, ecs_task_id):
        response = self.aws_ecs_client.describe_tasks(
            cluster=f'{self.campaign_id}-cluster',
            tasks=[ecs_task_id]
        )
        assert response, f"get_task_details failed for task_name {self.task_name}"
        return response

    def get_interface_details(self, interface_id):
        response = self.aws_ec2_client.describe_network_interfaces(
            NetworkInterfaceIds=[interface_id],
        )
        assert response, f"get_interface_details failed for task_name {self.task_name}"
        return response

    def add_task_entry(self, instruct_user_id, instruct_instance, instruct_command, instruct_args, task_host_name,
                       task_domain_name, attack_ip, portgroups, ecs_task_id, timestamp, end_time):
        task_status = 'starting'
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}-tasks',
            Key={
                'task_name': {'S': self.task_name}
            },
            UpdateExpression='set task_type=:task_type, task_context=:task_context, task_status=:task_status, '
                             'task_host_name=:task_host_name, task_domain_name=:task_domain_name, attack_ip=:attack_ip,'
                             'local_ip=:local_ip, portgroups=:portgroups, instruct_instances=:instruct_instances, '
                             'last_instruct_user_id=:last_instruct_user_id, '
                             'last_instruct_instance=:last_instruct_instance, '
                             'last_instruct_command=:last_instruct_command, last_instruct_args=:last_instruct_args, '
                             'last_instruct_time=:last_instruct_time, create_time=:create_time, '
                             'scheduled_end_time=:scheduled_end_time, user_id=:user_id, ecs_task_id=:ecs_task_id',
            ExpressionAttributeValues={
                ':task_type': {'S': self.task_type},
                ':task_context': {'S': self.task_context},
                ':task_status': {'S': task_status},
                ':task_host_name': {'S': task_host_name},
                ':task_domain_name': {'S': task_domain_name},
                ':attack_ip': {'S': attack_ip},
                ':local_ip': {'SS': ['None']},
                ':portgroups': {'SS': portgroups},
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
        assert response, f"add_task_entry failed for task_name {self.task_name}"
        return True

    def run_task(self):
        if 'task_type' not in self.detail:
            return format_response(400, 'failed', 'invalid detail', self.log)
        self.task_type = self.detail['task_type']

        task_type_entry = self.get_task_type_entry()
        if 'Item' not in task_type_entry:
            return format_response(404, 'failed', f'task_type {self.task_type} does not exist', self.log)

        # If portgroups are requested, do some sanity checks.
        if 'portgroups' in self.detail:
            portgroups = self.detail['portgroups']
            if not isinstance(portgroups, list):
                return format_response(400, 'failed', 'portgroups must be type list', self.log)
            if len(portgroups) > 5:
                return format_response(400, 'failed', 'portgroups limit exceeded', self.log)
        else:
            portgroups = ['None']

        if 'end_time' in self.detail and self.detail['end_time']:
            end_time = self.detail['end_time']
        else:
            end_time = 'None'
        if end_time != 'None':
            try:
                datetime.strptime(end_time, "%m/%d/%Y %H:%M:%S %z")
            except:
                return format_response(
                    400, 'failed', 'invalid detail: end_time must be formatted as "%m/%d/%Y %H:%M:%S %z"', self.log
                )

        # Verify that the task_name is unique.
        conflict = self.get_task_entry()
        if 'Item' in conflict:
            return format_response(409, 'failed', f'{self.task_name} already exists', self.log)

        task_host_name = 'None'
        task_domain_name = 'None'
        task_hosted_zone = None
        domain_entry = None
        # If host_name and domain_name are present in the run_task request, make sure the domain_name exists
        # and the host_name does not already exist for another task.
        if 'task_domain_name' in self.detail and 'task_host_name' in self.detail:
            task_domain_name = self.detail['task_domain_name']
            task_host_name = self.detail['task_host_name']
            if task_domain_name != 'None':
                length = len(f'{task_host_name}.{task_domain_name}')
                if length > 253:
                    return format_response(
                        400, 'failed', f'{task_host_name}.{task_domain_name} cannot exceed 253 characters', self.log
                    )
                valid_host_name = re.compile(
                    '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*'
                    '([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
                )
                host_name_match = valid_host_name.match(f'{task_host_name}.{task_domain_name}')
                if not host_name_match:
                    return format_response(
                        400, 'failed', f'{task_host_name}.{task_domain_name} is not DNS compliant', self.log
                    )
                domain_entry = self.get_domain_entry(task_domain_name)
                if 'Item' not in domain_entry:
                    return format_response(404, 'failed', f'domain_name {task_domain_name} does not exist', self.log)
                if task_host_name in domain_entry['Item']['host_names']['SS']:
                    return format_response(409, 'failed', f'{task_host_name} already exists', self.log)
                task_hosted_zone = domain_entry['Item']['hosted_zone']['S']

        securitygroups = []
        if 'None' not in portgroups:
            for portgroup in portgroups:
                portgroup_entry = self.get_portgroup_entry(portgroup)
                if 'Item' in portgroup_entry:
                    securitygroup_id = portgroup_entry['Item']['securitygroup_id']['S']
                    securitygroups.append(securitygroup_id)
                    if 'None' in portgroup_entry['Item']['tasks']['SS']:
                        portgroup_tasks = []
                    else:
                        portgroup_tasks = portgroup_entry['Item']['tasks']['SS']
                    portgroup_tasks.append(self.task_name)
                    self.update_portgroup_entry(portgroup, portgroup_tasks)
                else:
                    return format_response(404, 'failed', f'portgroup_name: {portgroup} does not exist', self.log)
        self.run_attack_task(securitygroups, end_time)
        # Log task execution details
        ecs_task_id = self.run_task_response['tasks'][0]['taskArn']
        t.sleep(15)
        ecs_task_details = self.get_ecstask_details(ecs_task_id)
        interface_id = ecs_task_details['tasks'][0]['attachments'][0]['details'][1]['value']
        interface_details = self.get_interface_details(interface_id)
        attack_ip = interface_details['NetworkInterfaces'][0]['Association']['PublicIp']
        recorded_info = {
            'task_executed': {
                'user_id': self.user_id, 'task_name': self.task_name, 'task_context': self.task_context,
                'task_type': self.task_type, 'task_domain_name': task_domain_name, 'task_host_name': task_host_name
            },
            'task_details': ecs_task_details,
            'interface_details': attack_ip
        }
        print(recorded_info)

        # Send Initialize command to the task
        instruct_user_id = 'None'
        instruct_instance = 'None'
        instruct_command = 'Initialize'
        instruct_args = {'no_args': 'True'}
        if 'end_time' in self.detail:
            end_time = self.detail['end_time']
        else:
            end_time = 'None'
        timestamp = datetime.now().strftime('%s')
        self.upload_object(instruct_user_id, instruct_instance, instruct_command, instruct_args, timestamp, end_time)

        # Create a Route53 resource record if a host_name/domain_name is requested for the task.
        if task_host_name != 'None' and task_domain_name != 'None':
            self.create_resource_record(task_hosted_zone, task_host_name, task_domain_name, attack_ip)
            if 'None' in domain_entry['Item']['tasks']['SS']:
                domain_tasks = []
            else:
                domain_tasks = domain_entry['Item']['tasks']['SS']
            domain_tasks.append(self.task_name)
            if 'None' in domain_entry['Item']['host_names']['SS']:
                domain_host_names = []
            else:
                domain_host_names = domain_entry['Item']['host_names']['SS']
            domain_host_names.append(task_host_name)
            self.update_domain_entry(task_domain_name, domain_tasks, domain_host_names)

        # Add task entry to tasks table in DynamoDB
        instruct_args_fixup = {'no_args': {'S': 'True'}}
        self.add_task_entry(instruct_user_id, instruct_instance, instruct_command, instruct_args_fixup, task_host_name,
                            task_domain_name, attack_ip, portgroups, ecs_task_id, timestamp, end_time)

        # Send response
        return format_response(200, 'success', 'execute task succeeded', None, attack_ip=attack_ip)
