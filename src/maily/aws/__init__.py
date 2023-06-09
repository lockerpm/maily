import boto3
from maily.config import AWS_REGION, AWS_SQS_URL


class AWS:
    def __init__(self):
        self.config = None
        self.service = None

    @property
    def client(self):
        if self.service == 'sqs':
            return boto3.resource(self.service, region_name=AWS_REGION).Queue(AWS_SQS_URL)
        return boto3.client(self.service, config=self.config, region_name=AWS_REGION)
