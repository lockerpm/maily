import boto3
from relay.logger import logger
from botocore.config import Config
from relay.config import AWS_REGION
from botocore.exceptions import ClientError
from relay.aws import AWS


class S3(AWS):
    def __init__(self):
        super().__init__()
        self.service = 's3'
        self.config = Config(
            region_name=AWS_REGION,
            retries={
                "max_attempts": 1,  # this includes the initial attempt to get the email
                "mode": "standard",
            }
        )

    def get_message_content_from_s3(self, bucket, object_key):
        if bucket and object_key:
            streamed_s3_object = self.client.get_object(Bucket=bucket, Key=object_key).get("Body")
            return streamed_s3_object.read()

    def remove_message_from_s3(self, bucket, object_key):
        if bucket is None or object_key is None:
            return False
        try:
            response = self.client.delete_object(Bucket=bucket, Key=object_key)
            return response.get("DeleteMarker")
        except ClientError as e:
            if e.response["Error"].get("Code", "") == "NoSuchKey":
                logger.error("s3_delete_object_does_not_exist: " + e.response["Error"])
            else:
                logger.error("s3_client_error_delete_email: " + e.response["Error"])
        return False
