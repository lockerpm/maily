import time
import requests
from maily.config import *
from maily.services.ses import ses_client
from maily.services.cloudflare import cf_client
from maily.services.route53 import route53_client


class DomainIdentity:
    def __init__(self, domain_name):
        self.domain_name = domain_name
        self.dns = route53_client

    def set_mail_from(self):
        """
        The mail-from records will help sending emails marked as send from this mail-from domain instead of AWS domains
        """
        mail_from_domain = f'mail.{self.domain_name}'
        self.dns.create_dns_record(record_type='MX', record_name=mail_from_domain,
                                   record_value=f'feedback-smtp.{AWS_REGION}.amazonses.com', priority=10)
        self.dns.create_dns_record(record_type='TXT', record_name=mail_from_domain,
                                   record_value='"v=spf1 include:amazonses.com ~all"')
        return ses_client.set_identity_mail_from_domain(self.domain_name, mail_from_domain)

    def create_domain(self):
        """
        Add a domain to authenticated list in AWS SES
        """
        if not self.domain_name.endswith(RELAY_DOMAIN):
            return False
        # Add DKIM records to verify
        dkim_tokens = ses_client.get_dkim_tokens(self.domain_name)
        for token in dkim_tokens:
            record_name = f'{token}._domainkey.{self.domain_name}'
            record_value = f'{token}.dkim.amazonses.com'
            self.dns.create_dns_record(record_type='CNAME', record_name=record_name, record_value=record_value)

        # Add MX records to receive emails
        self.dns.create_dns_record(record_type='MX', record_name=self.domain_name,
                                   record_value=f'inbound-smtp.{AWS_REGION}.amazonaws.com', priority=10)

        # Set mail-from domain
        return self.set_mail_from()

    def delete_domain(self):
        """
        Remove all things related to this domain
        """
        # Remove DKIM records
        dkim_tokens = ses_client.get_dkim_tokens(self.domain_name)
        for token in dkim_tokens:
            record_name = f'{token}._domainkey.{self.domain_name}'
            record_value = f'{token}.dkim.amazonses.com'
            self.dns.delete_dns_record(record_type='CNAME', record_name=record_name, record_value=record_value)

        # Remove MX records
        self.dns.delete_dns_record(record_type='MX', record_name=self.domain_name,
                                   record_value=f'inbound-smtp.{AWS_REGION}.amazonaws.com')

        # Remove mail-from records
        mail_from_domain = f'mail.{self.domain_name}'
        self.dns.delete_dns_record(record_type='MX', record_name=mail_from_domain,
                                   record_value=f'feedback-smtp.{AWS_REGION}.amazonses.com')
        self.dns.delete_dns_record(record_type='TXT', record_name=mail_from_domain,
                                   record_value='"v=spf1 include:amazonses.com ~all"')

        # Remove domain identity in SES
        ses_client.delete_identity(self.domain_name)

        return True
