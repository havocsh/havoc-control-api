import re
import json
import boto3


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


class Retrieve:

    def __init__(self, region, campaign_id, detail: dict, log):
        self.region = region
        self.campaign_id = campaign_id
        self.detail = detail
        self.log = log
        self.task_name = None
        self.__aws_s3_client = None
        self.__aws_dynamodb_client = None

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

    def get_task_entry(self):
        return self.aws_dynamodb_client.get_item(
            TableName=f'{self.campaign_id}-tasks',
            Key={
                'task_name': {'S': self.task_name}
            }
        )

    def retrieve_commands(self):
        if 'task_name' not in self.detail:
            return format_response(400, 'failed', 'invalid detail', self.log)
        self.task_name = self.detail['task_name']

        command_list = []
        task_entry = self.get_task_entry()
        if 'Item' not in task_entry:
            return format_response(404, 'failed', f'task {self.task_name} does not exist', self.log)

        list_objects_response = self.aws_s3_client.list_objects_v2(
            Bucket=f'{self.campaign_id}-workspace',
            Prefix=self.task_name + '/'
        )
        assert list_objects_response, f"list_objects_v2 failed for task_name {self.task_name}"
        file_list = []
        regex = f'{self.task_name}/(.*)'
        if 'Contents' in list_objects_response:
            for l in list_objects_response['Contents']:
                search = re.search(regex, l['Key'])
                if search.group(1):
                    file_list.append(l['Key'])
            for file_entry in file_list:
                get_object_response = self.aws_s3_client.get_object(
                    Bucket=f'{self.campaign_id}-workspace',
                    Key=file_entry
                )
                assert get_object_response, f"get_object failed for task_name {self.task_name}, key {file_entry}"
                interaction = json.loads(get_object_response['Body'].read().decode('utf-8'))
                command_list.append(interaction)
                delete_object_response = self.aws_s3_client.delete_object(
                    Bucket=f'{self.campaign_id}-workspace',
                    Key=file_entry
                )
                assert delete_object_response, f"delete_object failed for task_name {self.task_name}, key {file_entry}"

        return format_response(200, 'success', 'get_commands succeeded', None, commands=command_list)
