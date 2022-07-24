import gc
import json
import time
import shlex
import boto3
import OpenSSL
from relay.config import *
from codetiming import Timer
from relay.logger import logger
from botocore.exceptions import ClientError
from relay.sns import verify_from_sns, validate_sns_header, sns_inbound_logic


class Queue:
    def __init__(self):
        self.queue = self.create_client()
        self.halt_requested = False

    @staticmethod
    def process_message(message):
        """
        Process an SQS message, which may include sending an email.
        """

        results = {"success": True, "sqs_message_id": message.message_id}
        raw_body = message.body
        try:
            json_body = json.loads(raw_body)
        except ValueError as e:
            results.update(
                {
                    "success": False,
                    "error": f"Failed to load message.body: {e}",
                    "message_body_quoted": shlex.quote(raw_body),
                }
            )
            return results
        try:
            verified_json_body = verify_from_sns(json_body)
        except (KeyError, OpenSSL.crypto.Error) as e:
            logger.error(f"Failed SNS verification: {str(e)}")
            results.update(
                {
                    "success": False,
                    "error": f"Failed SNS verification: {e}",
                }
            )
            return results
        topic_arn = verified_json_body["TopicArn"]
        message_type = verified_json_body["Type"]
        error_details = validate_sns_header(topic_arn, message_type)
        if error_details:
            results["success"] = False
            results.update(error_details)
            return results

        try:
            sns_inbound_logic(message_type, verified_json_body)
        except ClientError as e:
            temp_errors = ["throttling", "pause"]
            lower_error_code = e.response["Error"]["Code"].lower()
            if any(temp_error in lower_error_code for temp_error in temp_errors):
                logger.error(f'"temporary" error, sleeping for 1s {e.response["Error"]}')
                with Timer(logger=None) as sleep_timer:
                    time.sleep(1)
                results["pause_count"] = 1
                results["pause_s"] = round(sleep_timer.last, 3)
                results["pause_error"] = e.response["Error"]

                try:
                    sns_inbound_logic(message_type, verified_json_body)
                    logger.info(f"[+] processed sqs message ID: {message.message_id}")
                except ClientError as e:
                    logger.error(f"[!] sqs_client_error {e.response['Error']}")
                    results.update(
                        {
                            "success": False,
                            "error": e.response["Error"],
                            "client_error_code": lower_error_code,
                        }
                    )
            else:
                logger.error(f"[!] sqs_client_error {e.response['Error']}")
                results.update(
                    {
                        "success": False,
                        "error": e.response["Error"],
                        "client_error_code": lower_error_code,
                    }
                )
        except Exception as e:
            results.update(
                {
                    "success": False,
                    "error": str(e)
                }
            )
        return results

    def poll_queue_for_messages(self):
        """
        Request a batch of messages, using the long-poll method.
        """
        with Timer(logger=None) as poll_timer:
            message_batch = self.queue.receive_messages(
                MaxNumberOfMessages=PROCESS_EMAIL_BATCH_SIZE,
                VisibilityTimeout=PROCESS_EMAIL_VISIBILITY_SECONDS,
                WaitTimeSeconds=PROCESS_EMAIL_WAIT_SECONDS,
            )
        return message_batch

    def process_message_batch(self, message_batch):
        """
        Process a batch of messages.
        """
        if not message_batch:
            return
        for message in message_batch:
            with Timer(logger=None) as message_timer:
                message_data = self.process_message(message)
                if message_data["success"] or PROCESS_EMAIL_DELETE_FAILED_MESSAGES:
                    message.delete()
            message_data["message_process_time_s"] = round(message_timer.last, 3)
            logger.info(f"[+] Message processed: {message_data}")

    def process_queue(self):
        """
        Process the SQS email queue until an exit condition is reached.
        """

        while not self.halt_requested:
            try:
                # Request and process a chunk of messages
                with Timer(logger=None) as cycle_timer:
                    message_batch = self.poll_queue_for_messages()
                    self.process_message_batch(message_batch)
                # Force garbage collection of boto3 SQS client resources
                gc.collect()
            except KeyboardInterrupt:
                self.halt_requested = True

    def handle(self):
        """
        Start the SQS here
        """
        logger.info(f"[+] Start listening the SQS {SQS_URL}")
        self.process_queue()
        logger.info(f"[+] Start listening the SQS {SQS_URL}")

    @staticmethod
    def create_client():
        """
        Create the SQS client.
        """
        sqs_client = boto3.resource("sqs", region_name=AWS_REGION)
        return sqs_client.Queue(SQS_URL)
