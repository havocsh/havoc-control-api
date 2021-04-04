import boto3, datetime, hashlib, hmac


class Login:

    def __init__(self, region, event):
        self.region = region
        self.event = event
        self.methodArn = event['methodArn']
        self.host = event['headers']['x-host']
        self.url = event['headers']['x-url']
        self.api_key = event['headers']['x-api-key']
        self.sig_date = event['headers']['x-sig-date']
        self.signature = event['headers']['x-signature']
        self.authorized = None
        self.user_id = None

    def sign(self, key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def getSignatureKey(self, key, date_stamp):
        kDate = self.sign(('havoc' + key).encode('utf-8'), date_stamp)
        kHost = self.sign(kDate, self.host)
        kSigning = self.sign(kHost, self.url)
        return kSigning

    def authorize_keys(self):
        client = boto3.client('dynamodb', region_name=self.region)
        response = client.query(
            TableName='authorizer',
            KeyConditionExpression='api_key = :key',
            ExpressionAttributeValues={
                ':key': {
                    'S': self.api_key
                }
            }
        )
        resp_api_key = None
        resp_secret_key = None
        resp_user_id = None
        if response['Items']:
            resp_api_key = response['Items'][0]['api_key']['S']
            resp_secret_key = response['Items'][0]['secret_key']['S']
            resp_user_id = response['Items'][0]['user_id']['S']

        if not self.host:
            self.authorized = False
            return self.authorized
        if not self.url:
            self.authorized = False
            return self.authorized
        if not self.api_key:
            self.authorized = False
            return self.authorized
        if not resp_user_id:
            self.authorized = False
            return self.authorized

        # Create signing key elements
        sig_date = datetime.datetime.strptime(self.sig_date, '%Y%m%dT%H%M%SZ')
        t = datetime.datetime.utcnow()
        local_date_stamp = t.strftime('%Y%m%d')

        # Ensure sig_date is within the last 5 seconds
        duration = t - sig_date
        duration_in_s = duration.total_seconds()
        if duration_in_s > 5 or duration_in_s < 0:
            self.authorized = False
            return self.authorized

        # Get signing_key
        signing_key = self.getSignatureKey(resp_secret_key, local_date_stamp)

        # Setup string to sign
        algorithm = 'HMAC-SHA256'
        credential_scope = local_date_stamp + '/' + self.host + '/' + self.url
        string_to_sign = algorithm + '\n' + self.sig_date + '\n' + credential_scope + hashlib.sha256(
            resp_api_key.encode('utf-8')).hexdigest()

        # Generate signature
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        if self.api_key == resp_api_key and self.signature == signature:
            self.authorized = True
            self.user_id = resp_user_id
        else:
            self.authorized = False
        return self.authorized

    def gen_response(self):

        def gen_policy(authorized):
            effect = "Allow" if authorized else "Deny"
            return {
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": self.methodArn
                }],
            }

        if self.authorized:
            policy = gen_policy(self.authorized)
            context = {'user_id': self.user_id, 'api_key': self.api_key}
            response = {
                'principalId': self.api_key,
                'policyDocument': policy,
                'context': context,
                'usageIdentifierKey': self.api_key
            }
            return response

        if not self.authorized:
            policy = gen_policy(self.authorized)
            context = {}
            response = {
                'context': context,
                'policyDocument': policy
            }
            return response