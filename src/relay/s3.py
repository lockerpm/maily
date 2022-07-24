import boto3
from relay.logger import logger
from botocore.config import Config
from relay.config import AWS_REGION
from botocore.exceptions import ClientError


class S3:
    def __init__(self):
        self.s3_client = self.create_client()

    @staticmethod
    def create_client():
        s3_config = Config(
            region_name=AWS_REGION,
            retries={
                "max_attempts": 1,  # this includes the initial attempt to get the email
                "mode": "standard",
            },
        )
        return boto3.client("s3", config=s3_config)

    def get_message_content_from_s3(self, bucket, object_key):
        if bucket and object_key:
            streamed_s3_object = self.s3_client.get_object(Bucket=bucket, Key=object_key).get("Body")
            return streamed_s3_object.read()

    def remove_message_from_s3(self, bucket, object_key):
        if bucket is None or object_key is None:
            return False
        try:
            response = self.s3_client.delete_object(Bucket=bucket, Key=object_key)
            return response.get("DeleteMarker")
        except ClientError as e:
            if e.response["Error"].get("Code", "") == "NoSuchKey":
                logger.error("s3_delete_object_does_not_exist: " + e.response["Error"])
            else:
                logger.error("s3_client_error_delete_email: " + e.response["Error"])
        return False
