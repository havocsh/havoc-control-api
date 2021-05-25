import json
import boto3
import string, random


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


def generate_string(length, punctuation=False):
    assert type(length) is int and length > 0, "length must be an int greater than zero"
    if punctuation:
        id_characters = string.ascii_letters + string.digits + string.punctuation
    else:
        id_characters = string.ascii_letters + string.digits
    rand_string = ''.join(random.choice(id_characters) for i in range(length))
    return rand_string


class User:

    def __init__(self, campaign_id, region, user_id, detail: dict, log):
        """
        Create, update and delete users
        """
        self.region = region
        self.campaign_id = campaign_id
        self.user_id = user_id
        self.detail = detail
        self.log = log
        self.manage_user_id = None

    @property
    def aws_dynamodb_client(self):
        """Returns the boto3 DynamoDB session (establishes one automatically if one does not already exist)"""
        if self.__aws_dynamodb_client is None:
            self.__aws_dynamodb_client = boto3.client('dynamodb', region_name=self.region)
        return self.__aws_dynamodb_client

    def query_api_keys(self, api_key):
        """Returns an api_key if one exists"""
        response = self.aws_dynamodb_client.query(
            TableName=f'{self.campaign_id}-authorizer',
            IndexName=f'{self.campaign_id}-ApiKeyIndex',
            KeyConditionExpression='api_key = :key',
            ExpressionAttributeValues={
                ':key': {
                    'S': api_key
                }
            }
        )
        return response

    def query_users(self):
        """Returns a list of users"""
        return self.aws_dynamodb_client.query(
            TableName=f'{self.campaign_id}-authorizer'
        )

    def get_user_details(self, user_id):
        """Returns details of a user"""
        response = self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-authorizer',
            Key={
                'user_id': {'S': user_id}
            }
        )
        if response:
            return response

    def add_user_attribute(self, attributes):
        """Add details to user, create the user if it does not exist"""
        for k, v in attributes.items():
            response = self.aws_dynamodb_client.update_item(
                TableName=f'{self.campaign_id}-authorizer',
                Key={
                    'user_id': {'S': self.manage_user_id}
                },
                UpdateExpression=f'set {k} = :a',
                ExpressionAttributeValues={':a': {'S': v}}
            )
            assert response, f"add_user_attribute failed for {self.manage_user_id}"

    def delete_user_id(self):
        """Deletes a user"""
        response = self.aws_dynamodb_client.delete_item(
            TableName=f'{self.campaign_id}-authorizer',
            Key={
                'user_id': {'S': self.manage_user_id}
            }
        )
        assert response, f'delete_user_id for {self.manage_user_id} failed'

    def create(self):
        calling_user = self.get_user_details(self.user_id)
        if calling_user['Item']['admin']['S'] != 'yes':
            response = format_response(403, 'failed', 'not allowed', self.log)
            return response
        if 'user_id' in self.detail:
            self.manage_user_id = self.detail['user_id']
        else:
            response = format_response(400, 'failed', 'invalid detail', self.log)
            return response
        existing_user = self.get_user_details(self.manage_user_id)
        if 'Item' in existing_user:
            response = format_response(409, 'failed', f'User ID {self.manage_user_id} already exists', self.log)
            return response
        api_key = None
        while not api_key:
            api_key = generate_string(12)
            existing_api_key = self.query_api_keys(api_key)
            if 'Items' in existing_api_key:
                api_key = None
        secret = generate_string(24, True)
        if 'admin' in self.detail and self.detail['admin'].lower() == 'yes':
            admin = 'yes'
        else:
            admin = 'no'
        user_attributes = {'api_key': api_key, 'secret': secret, 'admin': admin}
        self.add_user_attribute(user_attributes)
        response = format_response(
            200, 'success', None, self.log, user_id=self.manage_user_id, api_key=api_key, secret=secret, admin=admin
        )
        return response

    def delete(self):
        calling_user = self.get_user_details(self.user_id)
        if calling_user['Item']['admin']['S'] != 'yes':
            response = format_response(403, 'failed', 'not allowed', self.log)
            return response
        self.manage_user_id = self.detail['user_id']
        exists = self.get_user_details(self.manage_user_id)
        if 'Item' not in exists:
            response = format_response(404, 'failed', f'user_id {self.manage_user_id} does not exist', self.log)
            return response
        self.delete_user_id()
        response = format_response(200, 'success', None, self.log)
        return response

    def get(self):
        calling_user = self.get_user_details(self.user_id)
        if calling_user['Item']['admin']['S'] != 'yes':
            response = format_response(403, 'failed', 'not allowed', self.log)
            return response
        if 'user_id' not in self.detail:
            return format_response(400, 'failed', 'invalid detail', self.log)
        self.manage_user_id = self.detail['user_id']

        user_id_entry = self.get_user_details(self.manage_user_id)
        if 'Item' not in user_id_entry:
            return format_response(404, 'failed', f'user_id {self.manage_user_id} does not exist', self.log)

        user_id = user_id_entry['Item']['user_id']['S']
        admin = user_id_entry['Item']['admin']['S']
        api_key = user_id_entry['Item']['api_key']
        return format_response(200, 'success', None, None, user_id=user_id, admin=admin, api_key=api_key)

    def list(self):
        user_list = []
        users = self.query_users()
        for item in users['Items']:
            user_id = item['user_id']['S']
            user_list.append(user_id)
        return format_response(200, 'success', None, None, users=user_list)

    def update(self):
        calling_user = self.get_user_details(self.user_id)
        if calling_user['Item']['admin']['S'] != 'yes':
            response = format_response(403, 'failed', 'not allowed', self.log)
            return response
        self.manage_user_id = self.detail['user_id']
        exists = self.get_user_details(self.manage_user_id)
        if 'Item' not in exists:
            response = format_response(404, 'failed', f'user_id {self.manage_user_id} does not exist', self.log)
            return response
        new_user_id = None
        api_key = None
        secret = None
        admin = None
        user_attributes = {}
        if 'new_user_id' in self.detail:
            new_user_id = self.detail['new_user_id']
        if 'reset_keys' in self.detail:
            api_key = None
            while not api_key:
                api_key = generate_string(12)
                existing_api_key = self.query_api_keys(api_key)
                if 'Items' in existing_api_key:
                    api_key = None
            secret = generate_string(24, True)
        if 'admin' in self.detail:
            admin = self.detail['admin']
        if new_user_id:
            user_attributes['user_id'] = new_user_id
        if api_key and secret:
            user_attributes['api_key'] = api_key
            user_attributes['secret'] = secret
        if admin.lower() in ['yes', 'no']:
            user_attributes['admin'] = admin
        if not user_attributes:
            response = format_response(400, 'failed', 'invalid detail', self.log)
            return response
        self.add_user_attribute(user_attributes)
        response = format_response(
            200, 'success', None, self.log, user_id=new_user_id, api_key=api_key, secret=secret, admin=admin
        )
        return response

    def kill(self):
        return format_response(405, 'failed', 'command not accepted for this resource', self.log)