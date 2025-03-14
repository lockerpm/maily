import botocore
import pem
import html
import shlex
import OpenSSL
from maily.utils import *
from OpenSSL import crypto
from maily.logger import logger
from urllib.request import urlopen
from maily.aws.s3 import s3_client
from maily.aws.ses import ses_client
from botocore.exceptions import ClientError, ConnectionClosedError, SSLError
from email import message_from_bytes, policy
from django.utils.encoding import smart_bytes
from maily.exceptions import InReplyToNotFound
from maily.config import AWS_REGION, AWS_SNS_TOPIC, SUPPORTED_SNS_TYPES, REPLY_EMAIL
from maily.locker_api import get_reply_record_from_lookup_key, get_to_address, reply_allowed, \
    send_statistic_relay_address, get_relay_address_plan
from maily.domain_identity import DomainIdentity

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
        self.from_address = None
        self.to_address = None

    def response(self, code, message):
        return {'status_code': code, 'message': message, 'from': self.from_address, 'to': self.to_address}

    @property
    def sns_message(self):
        try:
            return json.loads(self.sqs_raw.body)
        except ValueError:
            return None

    @property
    def sns_message_body(self):
        try:
            return json.loads(self.sns_message["Message"])
        except json.JSONDecodeError:
            logger.error(f'SNS notification has non-JSON message body. Content: {self.sns_message["Message"]}')
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
    def mail_common_headers(self):
        return self.sns_mail.get("commonHeaders")

    @property
    def sns_receipt(self):
        return self.sns_message_body.get("receipt")

    @property
    def sns_message_content(self):
        try:
            return self.sns_message_body["content"].encode("utf-8")
        except (KeyError, AttributeError):
            return None

    def get_keys_from_headers(self):
        in_reply_to = None
        for header in self.sns_mail["headers"]:
            if header["name"].lower() == "in-reply-to":
                in_reply_to = header["value"]
                message_id_bytes = get_message_id_bytes(in_reply_to)
                return derive_reply_keys(message_id_bytes)
        if in_reply_to is None:
            raise InReplyToNotFound

    def handle_reply(self):
        try:
            lookup_key, encryption_key = self.get_keys_from_headers()
        except InReplyToNotFound:
            return self.response(400, "No In-Reply-To header")

        reply_record = get_reply_record_from_lookup_key(lookup_key)
        if reply_record is None:
            return self.response(400, "Unknown or stale In-Reply-To header")
        decrypted_metadata = json.loads(decrypt_reply_metadata(encryption_key, reply_record['encrypted_metadata']))
        subject = self.mail_common_headers.get("subject", "")
        self.to_address = decrypted_metadata.get("reply-to") or decrypted_metadata.get("from")
        try:
            self.to_address = extract_email_from_string(self.to_address)
        except AttributeError:
            return self.response(400, f"Cannot parse to_address from {self.to_address}")

        try:
            outbound_from_address = decrypted_metadata.get("to").split(',')[0].strip()
        except AttributeError:
            return self.response(400, f"Cannot get outbound_from_address from decrypted metadata {decrypted_metadata}")

        if not reply_allowed(self.from_address, self.to_address):
            return self.response(403, "Relay replies require a premium account")
        mail_content = self.get_text_html_attachments()
        if isinstance(mail_content, dict):
            return mail_content
        else:
            text_content, html_content, attachments = mail_content[0], mail_content[1], mail_content[2]

        message_body = {}
        if html_content:
            message_body["Html"] = {"Charset": "UTF-8", "Data": html_content}

        if text_content:
            message_body["Text"] = {"Charset": "UTF-8", "Data": text_content}

        ses_response = self.ses_relay_email(outbound_from_address, self.to_address,
                                            subject, message_body, attachments, self.sns_mail, reply_address=None)
        if ses_response['status_code'] == 200:
            statistic_result = send_statistic_relay_address(outbound_from_address, statistic_type="forwarded")
            if statistic_result is False:
                logger.warning(f"[!] Sending the forwarded statistic data to {outbound_from_address} failed")
        return ses_response

    def get_relay_recipient(self):
        # Go thru all To, Cc, and Bcc fields and
        # return the one that has a Relay domain

        # First check common headers for to or cc match
        headers_to_check = "to", "cc"
        for header in headers_to_check:
            if header in self.mail_common_headers:
                recipient = get_recipient_with_relay_domain(self.mail_common_headers[header])
                if recipient is not None:
                    return parseaddr(recipient)[1]

        # SES-SNS sends bcc in a different part of the message
        recipients = self.sns_receipt["recipients"]
        return get_recipient_with_relay_domain(recipients)

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
        except (KeyError, TypeError):
            logger.error(f'sns_inbound_message_receipt_malformed. receipt_action: {message_json_receipt["action"]}')
        return bucket, object_key

    def ses_relay_email(self, from_address, to_address, subject, message_body, attachments, mail,
                        reply_address=REPLY_EMAIL):
        response = ses_client.ses_send_raw_email(from_address, to_address, subject,
                                                 message_body, attachments, mail, reply_address)
        # Need to retry
        if response is None:
            return self.response(504, "SES client sent Raw Email failed. It needs to be re-sent")
        if response is False:
            return self.response(503, "SES client error on Raw Email")
        return self.response(200, "Sent email to final recipient")


    def get_text_html_attachments(self):
        if self.sns_message_content is None:
            # assume email content in S3
            bucket, object_key = self.get_bucket_and_key_from_s3_json()
            try:
                message_content = s3_client.get_message_content_from_s3(bucket, object_key)
                # Limit size is 25MB
                if len(message_content) > 26214400:
                    return self.response(400, "Attachments are larger than AWS allows")
            except ClientError as e:
                if e.response["Error"].get("Code", "") == "NoSuchKey":
                    logger.error(f's3_object_does_not_exist: {e.response["Error"]}')
                    return self.response(404, "Email not in S3")
                logger.error(f's3_client_error_get_email: {e.response["Error"]}')
                # we are returning a 500 so that SNS can retry the email processing
                # return self.response(503, "Cannot fetch the message content from S3")
                return self.response(504, "Fetch message from S3 error - boto3.ClientError")
            except (ConnectionClosedError, SSLError):
                return self.response(504, "Fetch message from S3 error - boto3.ConnectionClosedError")
        else:
            message_content = self.sns_message_content
        bytes_email_message = message_from_bytes(message_content, policy=policy.default)

        text_content, html_content, attachments = get_all_contents_email(bytes_email_message)
        return text_content, html_content, attachments

    def handle_sns_message(self):
        if self.sns_notification_type == "Bounce" or self.sns_event_type == "Bounce":
            return self.response(400, "We don't handle bounce message")

        if self.mail_common_headers is None:
            logger.error("[!] SNS message without commonHeaders")
            return self.response(400, "Received SNS notification without commonHeaders")

        if get_verdict(self.sns_receipt, "dmarc") == "FAIL":
            dmarc_policy = self.sns_receipt.get("dmarcPolicy", "none")
            if dmarc_policy == "reject":
                return self.response(400, "DMARC failure, policy is reject")

        self.to_address = self.get_relay_recipient()
        if self.to_address is None:
            return self.response(400, "Address does not exist")
        try:
            self.from_address = parseaddr(self.mail_common_headers["from"][0])[1]
        except KeyError:
            return self.response(400, f"Not found 'from' from mail common header {self.mail_common_headers}")
        if self.to_address == REPLY_EMAIL:
            return self.handle_reply()

        user_to_address = get_to_address(self.to_address)
        if user_to_address is None:
            return self.response(400, "Destination does not exist")

        try:
            relay_address_plan = get_relay_address_plan(self.to_address)
            enable_block_spam = relay_address_plan.get("block_spam")
            enable_relay_address = relay_address_plan.get("enabled")
            if not enable_relay_address:
                return self.response(400, f"Address {self.to_address} is disabled. Details: {relay_address_plan}")

            # Check spam
            if get_verdict(self.sns_receipt, "spam") == "FAIL" and enable_block_spam is True:
                # Tracking block spam event
                statistic_result = send_statistic_relay_address(relay_address=self.to_address, statistic_type="block_spam")
                if statistic_result is False:
                    logger.warning(f"[!] Sending the block spam statistic data to {self.to_address} failed")
                return self.response(400, "Address rejects spam")
        except (KeyError, AttributeError, AssertionError):
            logger.error()

        subject = self.mail_common_headers.get("subject", "")

        mail_content = self.get_text_html_attachments()
        if isinstance(mail_content, dict):
            return mail_content
        else:
            text_content, html_content, attachments = mail_content[0], mail_content[1], mail_content[2]

        message_body = {}
        if html_content:
            wrapped_html = wrap_html_email(original_html=html_content)
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
            ).format(alias=self.to_address, extra_msg=attachment_msg)
            wrapped_text = relay_header_text + text_content
            message_body["Text"] = {"Charset": "UTF-8", "Data": wrapped_text}

        formatted_from_address = generate_relay_from(self.from_address)
        # self.from_address = formatted_from_address
        ses_response = self.ses_relay_email(formatted_from_address, user_to_address, subject, message_body,
                                            attachments, self.sns_mail)
        # Tracking forwarded event HERE
        if ses_response['status_code'] == 200:
            statistic_result = send_statistic_relay_address(relay_address=self.to_address, statistic_type="forwarded")
            if statistic_result is False:
                logger.warning(f"[!] Sending the forwarded statistic data to {self.to_address} failed")
        return ses_response

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

    def handle_domain_identity(self):
        action = self.sns_message_body['action']
        domain = self.sns_message_body['domain']
        identity = DomainIdentity(domain)
        if action == 'create':
            if identity.create_domain():
                return self.response(200, f'Created domain {domain} successfully')
            else:
                return self.response(511, f'Created domain {domain} unsuccessfully')
        elif action == 'delete':
            identity.delete_domain()
            return self.response(200, f'Deleted domain {domain} successfully')
        return self.response(200, 'Domain Identity successfully')

    def sns_inbound_logic(self):
        if self.sns_message_type == "SubscriptionConfirmation":
            logger.info(f'SNS SubscriptionConfirmation: {self.sns_message["SubscribeURL"]}')
            return self.response(200, 'Logged SubscribeURL')
        elif self.sns_message_type == "Notification":
            return self.sns_notification()
        elif self.sns_message_type == "DomainIdentity":
            return self.handle_domain_identity()

        logger.error(f"SNS message type did not fall under the SNS inbound logic: {shlex.quote(self.sns_message_type)}")
        return self.response(400, 'Received SNS message with type not handled in inbound log')

    def sns_notification(self):
        if not self.sns_message_body:
            return self.response(400, 'Received SNS notification with non-JSON body')

        if self.sns_notification_type not in ["Received", "Bounce"] and self.sns_event_type != "Bounce":
            logger.error("SNS notification for unsupported type")
            return self.response(400, f'Received SNS notification for unsupported Type: '
                                      f'{html.escape(shlex.quote(self.sns_notification_type))}')
        response = self.handle_sns_message()
        bucket, object_key = self.get_bucket_and_key_from_s3_json()
        if response['status_code'] < 500:
            s3_client.remove_message_from_s3(bucket, object_key)
        return response
