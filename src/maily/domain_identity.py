import requests
from maily.config import *
from maily.logger import logger
from maily.aws.ses import ses_client


class DomainIdentity:
    def __init__(self, domain_name):
        self.domain_name = domain_name

    def set_mail_from(self):
        """
        The mail-from records will helps sending emails marked as send from this mail-from domain instead of AWS domains
        """
        mail_from_domain = f'mail.{self.domain_name}'
        self.create_dns_record('MX', mail_from_domain, 'feedback-smtp.us-east-1.amazonses.com', 10)
        self.create_dns_record('TXT', mail_from_domain, '"v=spf1 include:amazonses.com ~all"')
        return ses_client.set_identity_mail_from_domain(self.domain_name, mail_from_domain)

    def create_domain(self):
        """
        Add a domain to authenticated list in AWS SES
        """
        if not any(self.domain_name.endswith(f'{d}') for d in RELAY_DOMAINS):
            return False
        # Add DKIM records to verify
        dkim_tokens = ses_client.get_dkim_tokens(self.domain_name)
        for token in dkim_tokens:
            record_key = f'{token}._domainkey.{self.domain_name}'
            record_value = f'{token}.dkim.amazonses.com'
            self.create_dns_record('CNAME', record_key, record_value)

        # Add MX records to receive emails
        self.create_dns_record('MX', self.domain_name, f'inbound-smtp.{AWS_REGION}.amazonaws.com', 10)

        # Set mail-from domain
        response = self.set_mail_from()
        return response

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
        dkim_tokens = ses_client.get_dkim_tokens(self.domain_name)
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
        response = ses_client.delete_identity(self.domain_name)

        return True
