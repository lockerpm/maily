import os
import time
import boto3
import socket
import logging
import requests
import botocore.exceptions

AWS_REGION = os.getenv('AWS_REGION')
CF_ZONE = os.getenv('CF_ZONE')
CF_TOKEN = os.getenv('CF_TOKEN')
CF_HEADERS = {'Authorization': f'Bearer {CF_TOKEN}'}
CF_API = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE}/dns_records'
WHITELIST_DOMAINS = ['maily.org']


def get_logger():
    format_string = '%(asctime)s {hostname} %(levelname)s %(message)s'.format(**{'hostname': socket.gethostname()})
    format_log = logging.Formatter(format_string)
    format_log.converter = time.gmtime

    logging.basicConfig(level=logging.INFO)
    logging.disable(logging.DEBUG)
    for handler in logging.getLogger().handlers:
        logging.getLogger().removeHandler(handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(format_log)
    logging.getLogger().addHandler(stream_handler)

    return logging.getLogger()


logger = get_logger()


class Domain:
    def __init__(self, domain_name):
        self.ses_client = boto3.client('ses', region_name=AWS_REGION)
        self.domain_name = domain_name

    def get_dkim_tokens(self):
        """
        Get tokens to verify domain
        """
        dkim_tokens = self.ses_client.verify_domain_dkim(Domain=self.domain_name).get('DkimTokens')
        logger.info(f'[+] Getting records to authenticate domain from AWS SES')
        return dkim_tokens

    def set_mail_from(self):
        """
        The mail-from records will helps sending emails marked as send from this mail-from domain instead of AWS domains
        """
        mail_from_domain = f'mail.{self.domain_name}'
        try:
            response = self.ses_client.set_identity_mail_from_domain(
                Identity=self.domain_name,
                MailFromDomain=mail_from_domain,
                BehaviorOnMXFailure='UseDefaultValue'
            )
        except botocore.exceptions.ClientError:
            # When we delete a domain and recreate it shortly after
            # the new domain will be considered as not found
            # and we should wait until get the success status
            logger.info(f'[+] Waiting for 1 minutes until the domain identity available')

            time.sleep(60)
            self.set_mail_from()
            return
        self.create_dns_record('MX', mail_from_domain, 'feedback-smtp.us-east-1.amazonses.com', 10)
        self.create_dns_record('TXT', mail_from_domain, '"v=spf1 include:amazonses.com ~all"')

    def create_domain(self):
        """
        Add a domain to authenticated list in AWS SES
        """
        if not any(self.domain_name.endswith(f'.{d}') for d in WHITELIST_DOMAINS):
            return False
        # Add DKIM records to verify
        dkim_tokens = self.get_dkim_tokens()
        for token in dkim_tokens:
            record_key = f'{token}._domainkey.{self.domain_name}'
            record_value = f'{token}.dkim.amazonses.com'
            self.create_dns_record('CNAME', record_key, record_value)

        # Add MX records to receive emails
        self.create_dns_record('MX', self.domain_name, f'inbound-smtp.{AWS_REGION}.amazonaws.com', 10)

        # Set mail-from domain
        self.set_mail_from()
        return True

    @staticmethod
    def create_dns_record(record_type, record_key, record_value, priority=None):
        """
        Create DNS records in Cloudflare
        """
        payload = {"type": record_type, "name": record_key, "content": record_value}
        if priority:
            payload["priority"] = priority
        r = requests.post(CF_API, headers=CF_HEADERS, json=payload)
        logger.info(f'[+] Created record {record_type} {record_key} {record_value}')
        return r

    @staticmethod
    def delete_dns_record(record_type, record_key, record_value):
        """
        Delete a DNS record in Cloudflare
        """
        url = f'{CF_API}?type={record_type}&name={record_key}&content={record_value}&page=1&per_page=100&match=all'
        r = requests.get(url, headers=CF_HEADERS)
        for record in r.json()['result']:
            url = f'{CF_API}/{record["id"]}'
            requests.delete(url, headers=CF_HEADERS)
            logger.info(f'[+] Deleted record {record_type} {record_key} {record_value}')

    def delete_domain(self):
        """
        Remove all things related to this domain
        """
        # Remove DKIM records
        dkim_tokens = self.get_dkim_tokens()
        for token in dkim_tokens:
            record_key = f'{token}._domainkey.{self.domain_name}'
            record_value = f'{token}.dkim.amazonses.com'
            self.delete_dns_record('CNAME', record_key, record_value)

        # Remove MX records
        self.delete_dns_record('MX', self.domain_name, f'inbound-smtp.{AWS_REGION}.amazonaws.com')

        # Remove mail-from records
        mail_from_domain = f'mail.{self.domain_name}'
        self.delete_dns_record('MX', mail_from_domain, 'feedback-smtp.us-east-1.amazonses.com')
        self.delete_dns_record('TXT', mail_from_domain, '"v=spf1 include:amazonses.com ~all"')

        # Remove domain identity in SES
        response = self.ses_client.delete_identity(Identity=self.domain_name)

        return True

    def get_domain_status(self):
        """
        Check the status of a domain
        :return: Pending | Success | Failed | TemporaryFailure | NotStarted
        """
        response = self.ses_client.get_identity_dkim_attributes(Identities=[self.domain_name])
        try:
            return response['DkimAttributes'][self.domain_name]['DkimVerificationStatus']
        except KeyError:
            return 'NotStarted'


d = Domain('trung3.maily.org')
# d.create_domain()
d.delete_domain()
x = d.get_domain_status()
print(x)
