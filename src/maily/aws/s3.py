import time

from maily.aws import AWS
from maily.logger import logger
from botocore.config import Config
from maily.config import AWS_REGION
from botocore.exceptions import ClientError, ReadTimeoutError


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
            tries = 0
            while True:
                try:
                    streamed_s3_object = self.client.get_object(Bucket=bucket, Key=object_key).get("Body")
                    return streamed_s3_object.read()
                except ReadTimeoutError:
                    tries += 1
                    if tries > 5:
                        raise
                    time.sleep(3)

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


s3_client = S3()
