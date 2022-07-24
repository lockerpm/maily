import boto3
from relay.config import AWS_REGION


class AWS:
    def __init__(self):
        self.config = None
        self.service = None

    @property
    def client(self):
        return boto3.client(self.service, config=self.config, region_name=AWS_REGION)
