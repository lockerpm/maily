import os
import html
import json
import shlex
from relay.s3 import S3
from relay.ses import SES
from relay.utils import *
from relay import ROOT_PATH
from jinja2 import Template
from relay.logger import logger
from relay.config import RELAY_DOMAIN
from tempfile import SpooledTemporaryFile
from botocore.exceptions import ClientError
from email import message_from_bytes, policy


class Message:
    def __init__(self, body):
        self.body = body
        self.msg = None

    @property
    def event_type(self):
        return self.msg.get("eventType")

    @property
    def notification_type(self):
        return self.msg.get("notificationType")

    @property
    def mail(self):
        return self.msg.get("mail")

    @property
    def receipt(self):
        return self.msg.get("receipt")

    @property
    def message_content(self):
        try:
            return self.msg["content"].encode("utf-8")
        except (KeyError, AttributeError):
            return None

    @staticmethod
    def get_recipient_with_relay_domain(recipients):
        domains_to_check = [RELAY_DOMAIN]
        for recipient in recipients:
            for domain in domains_to_check:
                if domain in recipient:
                    return recipient
        return None

    def get_relay_recipient(self):
        # Go thru all To, Cc, and Bcc fields and
        # return the one that has a Relay domain

        # First check common headers for to or cc match
        headers_to_check = "to", "cc"
        common_headers = self.mail["commonHeaders"]
        for header in headers_to_check:
            if header in common_headers:
                recipient = self.get_recipient_with_relay_domain(common_headers[header])
                if recipient is not None:
                    return parseaddr(recipient)[1]

        # SES-SNS sends bcc in a different part of the message
        recipients = self.receipt["recipients"]
        return self.get_recipient_with_relay_domain(recipients)

    def get_bucket_and_key_from_s3_json(self):
        bucket = None
        object_key = None
        if isinstance(self.receipt, dict) and "action" in self.receipt:
            message_json_receipt = self.receipt
        else:
            is_bounce_notification = self.notification_type == "Bounce" or self.event_type == "Bounce"
            if not is_bounce_notification:
                # TODO: sns inbound notification does not have 'receipt'
                # we need to look into this more
                logger.error(f"[!] sns_inbound_message_without_receipt. message_json_keys: {self.msg.keys()}")
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
        if self.message_content is None:
            # assume email content in S3
            bucket, object_key = self.get_bucket_and_key_from_s3_json()
            s3 = S3()
            message_content = s3.get_message_content_from_s3(bucket, object_key)
        else:
            message_content = self.message_content
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
        return 'me@trungnh.com'

    def sns_message(self):
        if self.notification_type == "Bounce" or self.event_type == "Bounce":
            return {'status_code': 400, 'message': "We don't handle bounce message"}
        if "commonHeaders" not in self.mail:
            logger.error("[!] SNS message without commonHeaders")
            return {'status_code': 400, 'message': "Received SNS notification without commonHeaders"}
        common_headers = self.mail["commonHeaders"]

        to_address = self.get_relay_recipient()
        if to_address is None:
            return {'status_code': 400, 'message': "Address does not exist"}

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

        user_to_address = self.get_to_address(to_address)
        formatted_from_address = generate_relay_from(from_address)
        ses = SES()
        response = ses.ses_relay_email(formatted_from_address, user_to_address, subject, message_body, attachments)
        return response

    @property
    def valid(self):
        try:
            self.msg = json.loads(self.body["Message"])
        except json.JSONDecodeError:
            logger.error(f'SNS notification has non-JSON message body. Content: {self.body["Message"]}')
            return False
        return True

    def sns_notification(self):
        if not self.valid:
            return {'status_code': 400, 'message': 'Received SNS notification with non-JSON body'}

        if self.notification_type not in ["Received", "Bounce"] and self.event_type != "Bounce":
            logger.error("SNS notification for unsupported type")
            return {
                'status_code': 400,
                'message': f'Received SNS notification for unsupported Type: '
                           f'{html.escape(shlex.quote(self.notification_type))}'
            }
        response = self.sns_message()
        bucket, object_key = self.get_bucket_and_key_from_s3_json()
        if response['status_code'] < 500:
            s3 = S3()
            s3.remove_message_from_s3(bucket, object_key)
        return response
