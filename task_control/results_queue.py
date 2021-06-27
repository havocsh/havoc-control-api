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

    def __init__(self, campaign_id, task_name, region, detail: dict, user_id, log):
        self.campaign_id = campaign_id
        self.task_name = task_name
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

    def query_queue(self, start_timestamp, end_timestamp):
        queue_results = {'Items': []}
        scan_kwargs = {
            'TableName': f'{self.campaign_id}-queue',
            'KeyConditionExpression': 'task_name = :task_name AND run_time BETWEEN :start_time AND :end_time',
            'ExpressionAttributeValues': {
                ':task_name': {'S': self.task_name},
                ':start_time': {'N': start_timestamp},
                ':end_time': {'N': end_timestamp}
            }
        }

        done = False
        start_key = None
        while not done:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            response = self.aws_client.query(**scan_kwargs)
            for item in response['Items']:
                queue_results['Items'].append(item)
            start_key = response.get('LastEvaluatedKey', None)
            done = start_key is None
        return queue_results

    def get_results(self):

        queue_list = []

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

        # Assign query parameters
        start_timestamp = str(int(datetime.timestamp(start)))
        end_timestamp = str(int(datetime.timestamp(end)))
            
        # Run query
        queue_data = self.query_queue(start_timestamp, end_timestamp)
        if queue_data:
            for item in queue_data['Items']:
                run_time = item['run_time']['N']
                task_name = item['task_name']['S']
                task_type = item['task_type']['S']
                task_context = item['task_context']['S']
                task_response = item['task_response']['S']
                attack_ip = item['attack_ip']['S']
                local_ip = item['local_ip']['S']
                instruct_user_id = item['user_id']['S']
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

                # Add queue entry to results
                queue_list.append({'task_name': task_name, 'task_type': task_type, 'task_context': task_context,
                                   'task_attack_ip': attack_ip, 'task_local_ip': local_ip,
                                   'instruct_user_id': instruct_user_id, 'instruct_instance': instruct_instance,
                                   'instruct_command': instruct_command, 'instruct_args': instruct_args_fixup,
                                   'task_response': task_response, 'run_time': run_time})

        return format_response(200, 'success', 'get_results succeeded', None, queue=queue_list)
