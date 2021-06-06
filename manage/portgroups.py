import os
import json
import boto3
from datetime import datetime


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


class Portgroup:

    def __init__(self, campaign_id, region, user_id, detail: dict, log):
        """
        Instantiate a Portgroup instance
        """
        self.campaign_id = campaign_id
        self.region = region
        self.user_id = user_id
        self.detail = detail
        self.log = log
        self.vpc_id = os.environ['VPC_ID']
        self.portgroup_name = None
        self.__aws_dynamodb_client = None
        self.__aws_ec2_client = None

    @property
    def aws_dynamodb_client(self):
        """Returns the boto3 DynamoDB session (establishes one automatically if one does not already exist)"""
        if self.__aws_dynamodb_client is None:
            self.__aws_dynamodb_client = boto3.client('dynamodb', region_name=self.region)
        return self.__aws_dynamodb_client

    @property
    def aws_ec2_client(self):
        """Returns the boto3 ECS session (establishes one automatically if one does not already exist)"""
        if self.__aws_ec2_client is None:
            self.__aws_ec2_client = boto3.client('ec2', region_name=self.region)
        return self.__aws_ec2_client

    def query_portgroups(self):
        portgroups = {'Items': []}
        scan_kwargs = {'TableName': f'{self.campaign_id}-portgroups'}
        done = False
        start_key = None
        while not done:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            response = self.aws_dynamodb_client.scan(**scan_kwargs)
            portgroups['Items'].append(response.get('Items', []))
            start_key = response.get('LastEvaluatedKey', None)
            done = start_key is None
        return portgroups

    def get_portgroup_entry(self):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-portgroups',
            Key={
                'portgroup_name': {'S': self.portgroup_name}
            }
        )

    def get_portgroup_details(self, securitygroup_id):
        return self.aws_ec2_client.describe_security_groups(
            GroupIds=[securitygroup_id]
        )

    def create_portgroup_entry(self, description, timestamp):
        ec2_response = self.aws_ec2_client.create_security_group(
            Description=description,
            GroupName=self.portgroup_name,
            VpcId=self.vpc_id
        )
        securitygroup_id = ec2_response['GroupId']
        tasks = 'None'
        dynamodb_response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}-portgroups',
            Key={
                'portgroup_name': {'S': self.portgroup_name}
            },
            UpdateExpression='set securitygroup_id=:securitygroup_id, portgroup_description=:portgroup_description, '
                             'tasks=:tasks, create_time=:create_time, user_id=:user_id',
            ExpressionAttributeValues={
                ':securitygroup_id': {'S': securitygroup_id},
                ':portgroup_description': {'S': description},
                ':tasks': {'SS': [tasks]},
                ':create_time': {'S': timestamp},
                ':user_id': {'S': self.user_id}
            }
        )
        if securitygroup_id and dynamodb_response:
            return True
        else:
            return False

    def delete_portgroup_entry(self, securitygroup_id):
        ec2_response = self.aws_ec2_client.delete_security_group(
            GroupId=securitygroup_id
        )
        dynamodb_response = self.aws_dynamodb_client.delete_item(
            TableName=f'{self.campaign_id}-portgroups',
            Key={
                'portgroup_name': {'S': self.portgroup_name}
            }
        )
        if ec2_response and dynamodb_response:
            return True
        else:
            return False

    def update_portgroup_entry(self, securitygroup_id, ip_ranges, port, ip_protocol, portgroup_action):
        if portgroup_action == 'add':
            response = self.aws_ec2_client.authorize_security_group_ingress(
                GroupId=securitygroup_id,
                IpPermissions=[
                    {
                        'FromPort': port,
                        'ToPort': port,
                        'IpProtocol': ip_protocol,
                        'IpRanges': ip_ranges
                    }
                ]
            )
        else:
            response = self.aws_ec2_client.revoke_security_group_ingress(
                GroupId=securitygroup_id,
                IpPermissions=[
                    {
                        'FromPort': port,
                        'ToPort': port,
                        'IpProtocol': ip_protocol,
                        'IpRanges': ip_ranges
                    }
                ]
            )
        assert response, f"update_portgroup_entry failed for portgroup_name {self.portgroup_name}"
        return True

    def create(self):
        portgroup_details = ['portgroup_name', 'portgroup_description']
        for i in portgroup_details:
            if i not in self.detail:
                return format_response(400, 'failed', 'invalid detail', self.log)
        self.portgroup_name = self.detail['portgroup_name']
        portgroup_description = self.detail['portgroup_description']
        timestamp = datetime.now().strftime('%s')

        conflict = self.get_portgroup_entry()
        if 'Item' in conflict:
            return format_response(409, 'failed', f'{self.portgroup_name} already exists', self.log)

        try:
            self.create_portgroup_entry(portgroup_description, timestamp)
            return format_response(200, 'success', 'create portgroup succeeded', None)
        except:
            return format_response(500, 'failed', 'create portgroup failed', self.log)

    def delete(self):
        if 'portgroup_name' not in self.detail:
            return format_response(400, 'failed', 'invalid detail', self.log)
        self.portgroup_name = self.detail['portgroup_name']

        # Get portgroup details
        portgroup_entry = self.get_portgroup_entry()
        if 'Item' not in portgroup_entry:
            return format_response(404, 'failed', f'portgroup {self.portgroup_name} does not exist', self.log)
        securitygroup_id = portgroup_entry['Item']['securitygroup_id']['S']
        tasks = portgroup_entry['Item']['tasks']['SS']

        # Verify that portgroup is not associated with active tasks
        if 'None' not in tasks:
            return format_response(409, 'failed', 'cannot delete portgroup that is assigned to active tasks', self.log)

        # Delete security group
        try:
            self.delete_portgroup_entry(securitygroup_id)
            return format_response(200, 'success', 'delete portgroup succeeded', None)
        except:
            return format_response(500, 'failed', 'delete portgroup failed', self.log)

    def get(self):
        if 'portgroup_name' not in self.detail:
            return format_response(400, 'failed', 'invalid detail', self.log)
        self.portgroup_name = self.detail['portgroup_name']

        portgroup_entry = self.get_portgroup_entry()
        if 'Item' not in portgroup_entry:
            return format_response(404, 'failed', f'portgroup {self.portgroup_name} does not exist', self.log)

        securitygroup_id = portgroup_entry['Item']['securitygroup_id']['S']
        portgroup_description = portgroup_entry['Item']['portgroup_description']['S']
        associated_tasks = portgroup_entry['Item']['tasks']['SS']
        portgroup_creator_id = portgroup_entry['Item']['user_id']['S']
        create_time = portgroup_entry['Item']['create_time']['S']
        portgroup_rules = []
        portgroup_details = self.get_portgroup_details(securitygroup_id)
        portgroup_permissions = portgroup_details['SecurityGroups'][0]['IpPermissions']
        for permission in portgroup_permissions:
            from_port = permission['FromPort']
            ip_protocol = permission['IpProtocol']
            ip_ranges = permission['IpRanges']
            portgroup_rules.append({'port': from_port, 'ip_protocol': ip_protocol, 'ip_ranges': ip_ranges})
        return format_response(200, 'success', 'get portgroup succeeded', None, portgroup_name=self.portgroup_name,
                               portgroup_description=portgroup_description, associated_tasks=associated_tasks,
                               portgroup_creator_id=portgroup_creator_id, create_time=create_time,
                               portgroup=portgroup_rules)

    def list(self):
        portgroups_list = []
        portgroups = self.query_portgroups()
        for item in portgroups['Items']:
            self.portgroup_name = item['portgroup_name']['S']
            description = item['portgroup_description']['S']
            tasks = item['tasks']['SS']
            portgroup_creator_id = item['user_id']['S']
            create_time = item['create_time']['S']
            portgroups_list.append({'portgroup_name': self.portgroup_name, 'portgroup_description': description,
                                    'associated_tasks': tasks, 'portgroup_creator_id': portgroup_creator_id,
                                    'create_time': create_time})
        return format_response(200, 'success', 'list portgroups succeeded', None, portgroups=portgroups_list)

    def update(self):
        portgroup_details = ['portgroup_name', 'portgroup_action', 'ip_ranges', 'port', 'ip_protocol']
        for i in portgroup_details:
            if i not in self.detail:
                return format_response(400, 'failed', 'invalid detail', self.log)

        self.portgroup_name = self.detail['portgroup_name']
        portgroup_action = self.detail['portgroup_action']
        ip_ranges = self.detail['ip_ranges']
        port = self.detail['port']
        ip_protocol = self.detail['ip_protocol']

        if port == 55553:
            return format_response(400, 'failed', 'port 55553 is reserved', self.log)

        # Get portgroup details
        portgroup_entry = self.get_portgroup_entry()
        if 'Item' not in portgroup_entry:
            return format_response(404, 'failed', f'portgroup {self.portgroup_name} does not exist', self.log)
        securitygroup_id = portgroup_entry['Item']['securitygroup_id']['S']

        # Update security group
        try:
            self.update_portgroup_entry(securitygroup_id, ip_ranges, port, ip_protocol, portgroup_action)
            return format_response(200, 'success', 'update portgroup succeeded', None)
        except:
            if portgroup_action == 'add':
                return format_response(409, 'failed', 'portgroup rule already exists', self.log)
            else:
                return format_response(404, 'failed', 'portgroup rule not found', self.log)

    def kill(self):
        return format_response(405, 'failed', 'command not accepted for this resource', self.log)
