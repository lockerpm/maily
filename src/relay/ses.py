import boto3
from relay.logger import logger
from email.mime.text import MIMEText
from botocore.exceptions import ClientError
from email.mime.multipart import MIMEMultipart
from relay.utils import get_domains_from_settings
from email.mime.application import MIMEApplication
from relay.config import AWS_REGION, AWS_SES_CONFIGSET


class SES:
    def __init__(self):
        self.ses_client = self.create_client()

    @staticmethod
    def create_client():
        return boto3.client("ses", region_name=AWS_REGION)

    def ses_relay_email(self, from_address, to_address, subject, message_body, attachments):
        reply_address = "replies@%s" % get_domains_from_settings().get(
            "RELAY_FIREFOX_DOMAIN"
        )

        response = self.ses_send_raw_email(from_address, to_address, subject,
                                           message_body, attachments, reply_address)
        return response

    @staticmethod
    def add_body_to_message(msg, message_body):
        charset = "UTF-8"
        # Create a multipart/alternative child container.
        msg_body = MIMEMultipart("alternative")

        # Encode the text and HTML content and set the character encoding.
        # This step is necessary if you're sending a message with characters
        # outside the ASCII range.
        if "Text" in message_body:
            body_text = message_body["Text"]["Data"]
            text_part = MIMEText(body_text.encode(charset), "plain", charset)
            msg_body.attach(text_part)
        if "Html" in message_body:
            body_html = message_body["Html"]["Data"]
            html_part = MIMEText(body_html.encode(charset), "html", charset)
            msg_body.attach(html_part)
        # Attach the multipart/alternative child container to the multipart/mixed
        # parent container.
        msg.attach(msg_body)
        return msg

    @staticmethod
    def add_attachments_to_message(msg, attachments):
        # attach attachments
        for actual_att_name, attachment in attachments:
            # Define the attachment part and encode it using MIMEApplication.
            attachment.seek(0)
            att = MIMEApplication(attachment.read())

            # Add a header to tell the email client to treat this
            # part as an attachment, and to give the attachment a name.
            att.add_header("Content-Disposition", "attachment", filename=actual_att_name)
            # Add the attachment to the parent container.
            msg.attach(att)
            attachment.close()
        return msg

    @staticmethod
    def start_message_with_headers(subject, from_address, to_address, reply_address):
        # Create a multipart/mixed parent container.
        msg = MIMEMultipart("mixed")
        # Add subject, from and to lines.
        msg["Subject"] = subject
        msg["From"] = from_address
        msg["To"] = to_address
        msg["Reply-To"] = reply_address
        return msg

    def ses_send_raw_email(self, from_address, to_address, subject, message_body, attachments, reply_address):
        msg_with_headers = self.start_message_with_headers(subject, from_address, to_address, reply_address)
        msg_with_body = self.add_body_to_message(msg_with_headers, message_body)
        msg_with_attachments = self.add_attachments_to_message(msg_with_body, attachments)
        try:
            self.ses_client.send_raw_email(
                Source=from_address,
                Destinations=[to_address],
                RawMessage={
                    "Data": msg_with_attachments.as_string(),
                },
                ConfigurationSetName=AWS_SES_CONFIGSET,
            )
        except ClientError as e:
            logger.error(f'[!] ses_client_error_raw_email:{e.response["Error"]}')
            return {'status_code': 503, 'message': "SES client error on Raw Email"}
        return {'status_code': 200, 'message': "Sent email to final recipient"}
