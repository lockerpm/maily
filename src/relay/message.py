import os
import pem
import html
import json
import shlex
import base64
import OpenSSL
import requests
from relay.utils import *
from OpenSSL import crypto
from relay import ROOT_PATH
from jinja2 import Template
from relay.aws.s3 import S3
from relay.aws.ses import SES
from relay.logger import logger
from urllib.request import urlopen
from tempfile import SpooledTemporaryFile
from botocore.exceptions import ClientError
from email import message_from_bytes, policy
from django.utils.encoding import smart_bytes
from relay.config import RELAY_DOMAINS, AWS_REGION, AWS_SNS_TOPIC, SUPPORTED_SNS_TYPES, LOCKER_API_RELAY_DESTINATION

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


class Message:
    def __init__(self, sqs_raw):
        self.sqs_raw = sqs_raw

    @property
    def sns_message(self):
        try:
            return json.loads(self.sqs_raw.body)
        except ValueError:
            return None

    @property
    def sns_message_type(self):
        return self.sns_message.get("Type")

    @property
    def sns_event_type(self):
        return self.sns_message_body.get("eventType")

    @property
    def sns_notification_type(self):
        return self.sns_message_body.get("notificationType")

    @property
    def sns_mail(self):
        return self.sns_message_body.get("mail")

    @property
    def sns_receipt(self):
        return self.sns_message_body.get("receipt")

    @property
    def sns_message_content(self):
        try:
            return self.sns_message_body["content"].encode("utf-8")
        except (KeyError, AttributeError):
            return None

    @staticmethod
    def get_recipient_with_relay_domain(recipients):
        for recipient in recipients:
            for domain in RELAY_DOMAINS:
                if domain in recipient:
                    return recipient
        return None

    def get_relay_recipient(self):
        # Go thru all To, Cc, and Bcc fields and
        # return the one that has a Relay domain

        # First check common headers for to or cc match
        headers_to_check = "to", "cc"
        common_headers = self.sns_mail["commonHeaders"]
        for header in headers_to_check:
            if header in common_headers:
                recipient = self.get_recipient_with_relay_domain(common_headers[header])
                if recipient is not None:
                    return parseaddr(recipient)[1]

        # SES-SNS sends bcc in a different part of the message
        recipients = self.sns_receipt["recipients"]
        return self.get_recipient_with_relay_domain(recipients)

    def get_bucket_and_key_from_s3_json(self):
        bucket = None
        object_key = None
        if isinstance(self.sns_receipt, dict) and "action" in self.sns_receipt:
            message_json_receipt = self.sns_receipt
        else:
            is_bounce_notification = self.sns_notification_type == "Bounce" or self.sns_event_type == "Bounce"
            if not is_bounce_notification:
                # TODO: sns inbound notification does not have 'receipt'
                # we need to look into this more
                logger.error(f"[!] sns_inbound_message_without_receipt. message_json_keys: {self.sns_message.keys()}")
            return None, None

        try:
            if "S3" in message_json_receipt["action"]["type"]:
                bucket = message_json_receipt["action"]["bucketName"]
                object_key = message_json_receipt["action"]["objectKey"]
        except (KeyError, TypeError) as e:
            logger.error(f'sns_inbound_message_receipt_malformed. receipt_action: {message_json_receipt["action"]}')
        return bucket, object_key

    @staticmethod
    def get_attachment(part):
        fn = part.get_filename()
        payload = part.get_payload(decode=True)
        attachment = SpooledTemporaryFile(
            max_size=150 * 1000, prefix="relay_attachment_"  # 150KB max from SES
        )
        attachment.write(payload)
        return fn, attachment

    def get_all_contents(self, email_message):
        text_content = None
        html_content = None
        attachments = []
        if email_message.is_multipart():
            for part in email_message.walk():
                try:
                    if part.is_attachment():
                        att_name, att = self.get_attachment(part)
                        attachments.append((att_name, att))
                        continue
                    if part.get_content_type() == "text/plain":
                        text_content = part.get_content()
                    if part.get_content_type() == "text/html":
                        html_content = part.get_content()
                except KeyError:
                    # log the un-handled content type but don't stop processing
                    logger.error(f"part.get_content(). type:{part.get_content_type()}")
            if text_content is not None and html_content is None:
                html_content = urlize_and_linebreaks(text_content)
        else:
            if email_message.get_content_type() == "text/plain":
                text_content = email_message.get_content()
                html_content = urlize_and_linebreaks(email_message.get_content())
            if email_message.get_content_type() == "text/html":
                html_content = email_message.get_content()

        # TODO: if html_content is still None, wrap the text_content with our
        # header and footer HTML and send that as the html_content
        return text_content, html_content, attachments

    def get_text_html_attachments(self):
        if self.sns_message_content is None:
            # assume email content in S3
            bucket, object_key = self.get_bucket_and_key_from_s3_json()
            s3 = S3()
            message_content = s3.get_message_content_from_s3(bucket, object_key)
        else:
            message_content = self.sns_message_content
        bytes_email_message = message_from_bytes(message_content, policy=policy.default)

        text_content, html_content, attachments = self.get_all_contents(bytes_email_message)
        return text_content, html_content, attachments

    @staticmethod
    def wrap_html_email(original_html):
        """
        Add Relay banners, surveys, etc. to an HTML email
        """
        email_context = {
            "original_html": original_html
        }
        template_path = os.path.join(ROOT_PATH, "templates", "wrapped_email.html")
        return Template(open(template_path, encoding="utf-8").read()).render(email_context)

    @staticmethod
    def get_to_address(relay_address):
        """
        Connect to the Locker API to get the corresponding to_address with relay_address
        """
        try:
            r = requests.get(LOCKER_API_RELAY_DESTINATION + relay_address).json()
            return r['destination']
        except (requests.exceptions.ConnectionError, KeyError):
            return None

    def handle_sns_message(self):
        if self.sns_notification_type == "Bounce" or self.sns_event_type == "Bounce":
            return {'status_code': 400, 'message': "We don't handle bounce message"}
        if "commonHeaders" not in self.sns_mail:
            logger.error("[!] SNS message without commonHeaders")
            return {'status_code': 400, 'message': "Received SNS notification without commonHeaders"}

        to_address = self.get_relay_recipient()
        if to_address is None:
            return {'status_code': 400, 'message': "Address does not exist"}
        user_to_address = self.get_to_address(to_address)
        if user_to_address is None:
            return {'status_code': 400, 'message': "Destination does not exist"}

        common_headers = self.sns_mail["commonHeaders"]
        from_address = parseaddr(common_headers["from"][0])[1]
        subject = common_headers.get("subject", "")

        try:
            text_content, html_content, attachments = self.get_text_html_attachments()
        except ClientError as e:
            if e.response["Error"].get("Code", "") == "NoSuchKey":
                logger.error(f's3_object_does_not_exist: {e.response["Error"]}')
                return {'status_code': 404, 'message': "Email not in S3"}
            logger.error('s3_client_error_get_email: {e.response["Error"]}')
            # we are returning a 503 so that SNS can retry the email processing
            return {'status_code': 503, 'message': "Cannot fetch the message content from S3"}

        message_body = {}
        if html_content:
            wrapped_html = self.wrap_html_email(original_html=html_content)
            message_body["Html"] = {"Charset": "UTF-8", "Data": wrapped_html}

        if text_content:
            attachment_msg = (
                "Locker Private Email supports email forwarding (including attachments) "
                "of email up to 150KB in size.\n")
            relay_header_text = (
                "This email was sent to your alias "
                "{alias}. To stop receiving emails sent to this alias, "
                "update the forwarding settings in your dashboard.\n"
                "{extra_msg}---Begin Email---\n"
            ).format(alias=to_address, extra_msg=attachment_msg)
            wrapped_text = relay_header_text + text_content
            message_body["Text"] = {"Charset": "UTF-8", "Data": wrapped_text}

        formatted_from_address = generate_relay_from(from_address)
        ses = SES()
        response = ses.ses_relay_email(formatted_from_address, user_to_address, subject, message_body, attachments)
        return response

    def grab_keyfile(self):
        cert_url = self.sns_message["SigningCertURL"]
        cert_url_origin = f"https://sns.{AWS_REGION}.amazonaws.com/"
        if not (cert_url.startswith(cert_url_origin)):
            return None

        response = urlopen(cert_url)
        pem_file = response.read()
        # Extract the first certificate in the file and confirm it's a valid
        # PEM certificate
        certificates = pem.parse(smart_bytes(pem_file))

        # A proper certificate file will contain 1 certificate
        if len(certificates) != 1:
            logger.error("Invalid Certificate File: URL %s", cert_url)
            return None
        return pem_file

    def get_hash_format(self):
        if self.sns_message_type == "Notification":
            if "Subject" in self.sns_message.keys():
                return NOTIFICATION_HASH_FORMAT
            return NOTIFICATION_WITHOUT_SUBJECT_HASH_FORMAT
        return SUBSCRIPTION_HASH_FORMAT

    def verify_from_sns(self):
        pem_file = self.grab_keyfile()
        if pem_file is None:
            return False
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_file)
        signature = base64.decodebytes(self.sns_message["Signature"].encode("utf-8"))

        hash_format = self.get_hash_format()
        try:
            crypto.verify(cert, signature, hash_format.format(**self.sns_message).encode("utf-8"), "sha1")
        except OpenSSL.crypto.Error:
            return False
        return True

    def validate_sns_header(self):
        """
        Validate Topic ARN and SNS Message Type.

        If an error is detected, the return is a dictionary of error details.
        If no error is detected, the return is None.
        """
        topic_arn = self.sns_message["TopicArn"]

        if not topic_arn:
            error = "Received SNS request without Topic ARN."
        elif topic_arn not in AWS_SNS_TOPIC:
            error = "Received SNS message for wrong topic."
        elif not self.sns_message_type:
            error = "Received SNS request without Message Type."
        elif self.sns_message_type not in SUPPORTED_SNS_TYPES:
            error = "Received SNS message for unsupported Type."
        else:
            error = None
        if error:
            return {
                "error": error,
                "received_topic_arn": shlex.quote(topic_arn),
                "supported_topic_arn": sorted(AWS_SNS_TOPIC),
                "received_sns_type": shlex.quote(self.sns_message_type),
                "supported_sns_types": SUPPORTED_SNS_TYPES,
            }
        return None

    @property
    def sns_message_body(self):
        try:
            return json.loads(self.sns_message["Message"])
        except json.JSONDecodeError:
            logger.error(f'SNS notification has non-JSON message body. Content: {self.sns_message["Message"]}')
            return None

    def sns_inbound_logic(self):
        if self.sns_message_type == "SubscriptionConfirmation":
            logger.info(f'SNS SubscriptionConfirmation: {self.sns_message["SubscribeURL"]}')
            return {'status_code': 200, 'message': 'Logged SubscribeURL'}
        if self.sns_message_type == "Notification":
            return self.sns_notification()

        logger.error(f"SNS message type did not fall under the SNS inbound logic: {shlex.quote(self.sns_message_type)}")
        return {'status_code': 400, 'message': 'Received SNS message with type not handled in inbound log'}

    def sns_notification(self):
        if not self.sns_message_body:
            return {'status_code': 400, 'message': 'Received SNS notification with non-JSON body'}

        if self.sns_notification_type not in ["Received", "Bounce"] and self.sns_event_type != "Bounce":
            logger.error("SNS notification for unsupported type")
            return {
                'status_code': 400,
                'message': f'Received SNS notification for unsupported Type: '
                           f'{html.escape(shlex.quote(self.sns_notification_type))}'
            }
        response = self.handle_sns_message()
        bucket, object_key = self.get_bucket_and_key_from_s3_json()
        if response['status_code'] < 500:
            s3 = S3()
            s3.remove_message_from_s3(bucket, object_key)
        return response
