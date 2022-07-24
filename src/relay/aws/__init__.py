import boto3
from relay.config import AWS_REGION, SQS_URL


class AWS:
    def __init__(self):
        self.config = None
        self.service = None

    @property
    def client(self):
        if self.service == 'sqs':
            return boto3.resource(self.service, region_name=AWS_REGION).Queue(SQS_URL)
        return boto3.client(self.service, config=self.config, region_name=AWS_REGION)
