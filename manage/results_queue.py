import json
import boto3
from datetime import datetime
from datetime import timedelta


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


class Queue:

    def __init__(self, campaign_id, region, user_id, detail: dict, log):
        self.campaign_id = campaign_id
        self.region = region
        self.user_id = user_id
        self.detail = detail
        self.log = log
        self.__aws_client = None

    @property
    def aws_client(self):
        """Returns the boto3 session (establishes one automatically if one does not already exist)"""
        if self.__aws_client is None:
            self.__aws_client = boto3.client('dynamodb', region_name=self.region)
        return self.__aws_client

    def list(self):

        queue_list = []
        
        def query_queue(start_timestamp, end_timestamp, task_name):
            queue_results = {'Items': []}

            if task_name:
                scan_kwargs = {
                    'TableName': f'{self.campaign_id}-queue',
                    'filter_expression': 'task_name = :task_name',
                    'KeyConditionExpression': 'run_time BETWEEN :start_time and :end_time',
                    'expression_attribute_values': {
                        ':task_name': {'S': task_name},
                        ':start_time': {'N': start_timestamp},
                        ':end_time': {'N': end_timestamp}
                    }
                }
            else:
                scan_kwargs = {
                    'TableName': f'{self.campaign_id}-queue',
                    'filter_expression': None,
                    'KeyConditionExpression': 'run_time BETWEEN :start_time and :end_time',
                    'expression_attribute_values': {
                        ':start_time': {'N': start_timestamp},
                        ':end_time': {'N': end_timestamp}
                    }
                }

            done = False
            start_key = None
            while not done:
                if start_key:
                    scan_kwargs['ExclusiveStartKey'] = start_key
                response = self.aws_client.scan(**scan_kwargs)
                for item in response['Items']:
                    queue_results['Items'].append(item)
                start_key = response.get('LastEvaluatedKey', None)
                done = start_key is None
            return queue_results

        # Build query time range
        start_time = None
        if 'start_time' in self.detail:
            start_time = self.detail['start_time']
        end_time = None
        if 'end_time' in self.detail:
            end_time = self.detail['end_time']
        if start_time != '' and start_time is not None:
            start = datetime.strptime(start_time, "%m/%d/%Y %H:%M:%S")
        else:
            start = datetime.now() - timedelta(minutes=1440)

        if end_time != '' and end_time is not None:
            end = datetime.strptime(end_time, "%m/%d/%Y %H:%M:%S")
        else:
            end = datetime.now()

        # Assign additional query filters
        task_name = None
        if 'task_name' in self.detail:
            task_name = self.detail['task_name']

        start_timestamp = str(int(datetime.timestamp(start)))
        end_timestamp = str(int(datetime.timestamp(end)))
            
        # Run query
        queue_data = query_queue(start_timestamp, end_timestamp, task_name)
        if queue_data:
            for item in queue_data['Items']:
                run_time = item['run_time']['N']
                task_name = item['task_name']['S']
                task_result = item['task_result']['S']
                instruct_user_id = item['user_id']['S']
                instruct_object = item['instruct_object']['S']
                instruct_instance = item['instruct_instance']['S']
                instruct_command = item['instruct_command']['S']
                instruct_args = item['instruct_args']['M']
                instruct_args_fixup = {}
                for key, value in instruct_args.items():
                    if 'S' in value:
                        instruct_args_fixup[key] = value['S']
                    if 'N' in value:
                        instruct_args_fixup[key] = value['N']
                    if 'B' in value:
                        instruct_args_fixup[key] = value['B']
                attack_ip = item['attack_ip']['M']
                attack_ip_fixup = {}
                for key, value in attack_ip.items():
                    attack_ip_fixup[key] = value['S']

                # Add queue entry to results
                queue_list.append({'task_name': task_name, 'task_attack_ip': attack_ip,
                                   'instruct_user_id': instruct_user_id, 'instruct_object': instruct_object,
                                   'instruct_instance': instruct_instance, 'instruct_command': instruct_command,
                                   'instruct_args': instruct_args_fixup, 'task_result': task_result,
                                   'task_run_time': run_time})

        return format_response(200, 'success', 'list queue succeeded', None, queue=queue_list)

    def create(self):
        return format_response(405, 'failed', 'command not accepted for this resource', self.log)

    def delete(self):
        return format_response(405, 'failed', 'command not accepted for this resource', self.log)

    def get(self):
        return format_response(405, 'failed', 'command not accepted for this resource', self.log)

    def kill(self):
        return format_response(405, 'failed', 'command not accepted for this resource', self.log)

    def update(self):
        return format_response(405, 'failed', 'command not accepted for this resource', self.log)
