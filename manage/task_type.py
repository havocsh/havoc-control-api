import json
import boto3


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


class Registration:

    def __init__(self, campaign_id, region, user_id, detail: dict, log):
        """
        Register or deregister a task_type
        """
        self.region = region
        self.campaign_id = campaign_id
        self.user_id = user_id
        self.detail = detail
        self.log = log
        self.task_type = None
        self.source_image = None
        self.capabilities = None
        self.cpu = None
        self.memory = None
        self.__aws_dynamodb_client = None
        self.__aws_ecs_client = None

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

    def query_task_types(self):
        task_types = {'Items': []}
        scan_kwargs = {'TableName': f'{self.campaign_id}-task-types'}
        done = False
        start_key = None
        while not done:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            response = self.aws_dynamodb_client.scan(**scan_kwargs)
            for item in response['Items']:
                task_types['Items'].append(item)
            start_key = response.get('LastEvaluatedKey', None)
            done = start_key is None
        return task_types

    def get_task_type_entry(self):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-task-types',
            Key={
                'task_type': {'S': self.task_type}
            }
        )

    def add_task_type_entry(self, task_definition_arn):
        response = self.aws_dynamodb_client.update_item(
            TableName=f'{self.campaign_id}-task-types',
            Key={
                'task_type': {'S': self.task_type}
            },
            UpdateExpression='set task_type=:task_type, source_image=:source_image, user_id=:user_id, '
                             'task_definition_arn=:task_definition_arn, capabilities=:capabilities',
            ExpressionAttributeValues={
                ':task_type': {'S': self.task_type},
                ':source_image': {'S': self.source_image},
                ':user_id': {'S': self.user_id},
                ':task_definition_arn': {'S': task_definition_arn},
                ':capabilities': {'SS': self.capabilities}
            }
        )
        assert response, f"add_task_type_entry failed for task_type {self.task_type}"
        return True

    def remove_task_type_entry(self):
        response = self.aws_dynamodb_client.delete_item(
            TableName=f'{self.campaign_id}-task-types',
            Key={
                'task_type': {'S': self.task_type}
            }
        )
        assert response, f"remove_task_type_entry failed for task_type {self.task_type}"
        return True

    def add_ecs_task_definition(self):
        response = self.aws_ecs_client.register_task_definition(
            family=f'{self.campaign_id}-{self.task_type}',
            taskRoleArn=f'{self.campaign_id}-task-role',
            executionRoleArn=f'{self.campaign_id}-execution-role',
            networkMode='awsvpc',
            containerDefinitions=[
                {
                    'name': f'{self.campaign_id}-{self.task_type}',
                    'image': self.source_image,
                    'essential': True,
                    'entryPoint': [
                        '/bin/bash', '-c'
                    ],
                    'command': [
                        '/usr/bin/supervisord', '-c', '/etc/supervisor/conf.d/supervisord.conf'
                    ],
                    'logConfiguration': {
                        'logDriver': 'awslogs',
                        'options': {
                            'awslogs-group': self.campaign_id,
                            'awslogs-region': self.region,
                            'awslogs-stream-prefix': self.task_type
                        }
                    }
                }
            ],
            requiresCompatibilities=['FARGATE'],
            cpu=self.cpu,
            memory=self.memory,
            tags=[
                {
                    'key': 'campaign',
                    'value': self.campaign_id
                },
                {
                    'key': 'name',
                    'value': f'{self.campaign_id}-{self.task_type}'
                },
            ]
        )
        assert response, f"add_ecs_task_definition failed for task_type {self.task_type}"
        return response

    def remove_ecs_task_definition(self, task_definition_arn):
        response = self.aws_ecs_client.deregister_task_definition(
            taskDefinition=task_definition_arn
        )
        assert response, f"remove_ecs_task_definition failed for task_type {self.task_type}"
        return True

    def create(self):
        task_details = ['task_type', 'source_image', 'capabilities', 'cpu', 'memory']
        for i in task_details:
            if i not in self.detail:
                return format_response(400, 'failed', 'invalid detail', self.log)
        self.task_type = self.detail['task_type']
        self.source_image = self.detail['source_image']
        self.capabilities = self.detail['capabilities']
        self.cpu = self.detail['cpu']
        self.memory = self.detail['memory']

        # Verify that the task_type is unique
        conflict = self.get_task_type_entry()
        if conflict:
            return format_response(409, 'failed', f'Task type {self.task_type} already exists', self.log)

        # Add task type entry to task_types table in DynamoDB
        task_definition = self.add_ecs_task_definition()
        if task_definition['taskDefinition']['taskDefinitionArn']:
            task_definition_arn = task_definition['taskDefinition']['taskDefinitionArn']
        else:
            return format_response(500, 'failed', f'add_task_type failed for {self.task_type}', None)
        self.add_task_type_entry(task_definition_arn)

        # Send response
        return format_response(200, 'success', 'add task_type succeeded', None)

    def delete(self):
        if 'task_type' not in self.detail:
            return format_response(400, 'failed', 'invalid detail', self.log)
        self.task_type = self.detail['task_type']

        # Verify that the task_type exists
        exists = self.get_task_type_entry()
        if not exists:
            return format_response(404, 'failed', f'task_type {self.task_type} does not exist', self.log)

        # Remove task type entry from task_types table in DynamoDB
        task_definition_arn = exists['Item']['task_definition_arn']['S']
        remove_ecs_task = self.remove_ecs_task_definition(task_definition_arn)
        if not remove_ecs_task:
            return format_response(500, 'failed', f'remove_task_type failed for {self.task_type}', None)
        self.remove_task_type_entry()

        # Send response
        return format_response(200, 'success', 'remove task_type succeeded', None)

    def get(self):
        if 'task_type' not in self.detail:
            return format_response(400, 'failed', 'invalid detail', self.log)
        self.task_type = self.detail['task_type']
        capabilities_list = []
        task_type = self.get_task_type_entry()
        task_type_capabilities = task_type['Item']['capabilities']['SS']
        capabilities_list.append({'capabilities': task_type_capabilities})

        # Send response
        return format_response(200, 'success', 'get_task_type_capabilities succeeded', None,
                               capabilities=capabilities_list)

    def list(self):
        task_types_list = []
        task_types = self.query_task_types()
        for item in task_types['Items']:
            task_type = item['task_type']['S']
            source_image = item['source_image']['S']
            task_type_capabilities = item['capabilities']['SS']
            task_type_user_id = item['user_id']['S']
            task_types_list.append({'task_type': task_type, 'source_image': source_image,
                                    'capabilities': task_type_capabilities, 'user_id': task_type_user_id})

        # Send response
        return format_response(200, 'success', 'list_task_types succeeded', None, task_types=task_types_list)

    def kill(self):
        return format_response(405, 'failed', 'command not accepted for this resource', self.log)

    def update(self):
        return format_response(405, 'failed', 'command not accepted for this resource', self.log)


