import pem
import shlex
from relay.config import *
from relay.logger import logger
from relay.message import Message
from urllib.request import urlopen

NOTIFICATION_HASH_FORMAT = """Message
{Message}
MessageId
{MessageId}
Subject
{Subject}
Timestamp
{Timestamp}
TopicArn
{TopicArn}
Type
{Type}
"""

NOTIFICATION_WITHOUT_SUBJECT_HASH_FORMAT = """Message
{Message}
MessageId
{MessageId}
Timestamp
{Timestamp}
TopicArn
{TopicArn}
Type
{Type}
"""

SUBSCRIPTION_HASH_FORMAT = """Message
{Message}
MessageId
{MessageId}
SubscribeURL
{SubscribeURL}
Timestamp
{Timestamp}
Token
{Token}
TopicArn
{TopicArn}
Type
{Type}
"""

SUPPORTED_SNS_TYPES = [
    "SubscriptionConfirmation",
    "Notification",
]


def verify_from_sns(json_body):
    # pem_file = _grab_keyfile(json_body["SigningCertURL"])
    # cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_file)
    # signature = base64.decodebytes(json_body["Signature"].encode("utf-8"))
    #
    # hash_format = _get_hash_format(json_body)
    #
    # crypto.verify(
    #     cert, signature, hash_format.format(**json_body).encode("utf-8"), "sha1"
    # )
    return json_body


def _get_hash_format(json_body):
    message_type = json_body["Type"]
    if message_type == "Notification":
        if "Subject" in json_body.keys():
            return NOTIFICATION_HASH_FORMAT
        return NOTIFICATION_WITHOUT_SUBJECT_HASH_FORMAT

    return SUBSCRIPTION_HASH_FORMAT


def _grab_keyfile(cert_url):
    cert_url_origin = f"https://sns.{AWS_REGION}.amazonaws.com/"
    if not (cert_url.startswith(cert_url_origin)):
        raise SuspiciousOperation(
            f'SNS SigningCertURL "{cert_url}" did not start with "{cert_url_origin}"'
        )

    key_cache = caches[AWS_SNS_KEY_CACHE]

    pem_file = key_cache.get(cert_url)
    if not pem_file:
        response = urlopen(cert_url)
        pem_file = response.read()
        # Extract the first certificate in the file and confirm it's a valid
        # PEM certificate
        certificates = pem.parse(smart_bytes(pem_file))

        # A proper certificate file will contain 1 certificate
        if len(certificates) != 1:
            logger.error("Invalid Certificate File: URL %s", cert_url)
            raise ValueError("Invalid Certificate File")

        key_cache.set(cert_url, pem_file)
    return pem_file


def validate_sns_header(topic_arn, message_type):
    """
    Validate Topic ARN and SNS Message Type.

    If an error is detected, the return is a dictionary of error details.
    If no error is detected, the return is None.
    """
    if not topic_arn:
        error = "Received SNS request without Topic ARN."
    elif topic_arn not in AWS_SNS_TOPIC:
        error = "Received SNS message for wrong topic."
    elif not message_type:
        error = "Received SNS request without Message Type."
    elif message_type not in SUPPORTED_SNS_TYPES:
        error = "Received SNS message for unsupported Type."
    else:
        error = None

    if error:
        return {
            "error": error,
            "received_topic_arn": shlex.quote(topic_arn),
            "supported_topic_arn": sorted(AWS_SNS_TOPIC),
            "received_sns_type": shlex.quote(message_type),
            "supported_sns_types": SUPPORTED_SNS_TYPES,
        }
    return None


def sns_inbound_logic(message_type, json_body):
    if message_type == "SubscriptionConfirmation":
        logger.info(f'SNS SubscriptionConfirmation: {json_body["SubscribeURL"]}')
        return {'status_code': 200, 'message': 'Logged SubscribeURL'}
    if message_type == "Notification":
        message = Message(json_body)
        return message.sns_notification()

    logger.error(f"SNS message type did not fall under the SNS inbound logic: {shlex.quote(message_type)}")
    return {'status_code': 400, 'message': 'Received SNS message with type not handled in inbound log'}
