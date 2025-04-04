from maily.config import *
from maily.aws.ses import ses_client
from maily.aws.route53 import route53_client


class Route53DomainIdentity:
    def __init__(self, domain_name):
        self.domain_name = domain_name

    def set_mail_from(self):
        """
        The mail-from records will help sending emails marked as send from this mail-from domain instead of AWS domains
        """
        mail_from_domain = f'mail.{self.domain_name}'
        self.create_dns_record('MX', mail_from_domain, f'feedback-smtp.{AWS_REGION}.amazonses.com', 10)
        self.create_dns_record('TXT', mail_from_domain, f'"v=spf1 include:amazonses.com ~all"')
        return ses_client.set_identity_mail_from_domain(self.domain_name, mail_from_domain)

    def create_domain(self):
        """
        Add a domain to authenticated list in AWS SES and create DNS records in Route53
        """
        if not self.domain_name.endswith(RELAY_DOMAIN):
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
        Create DNS records in AWS Route53
        """
        if record_type == 'MX' and priority:
            record_value = f"{priority} {record_value}"
            
        return route53_client.create_dns_record(record_type, record_key, record_value)

    @staticmethod
    def delete_dns_record(record_type, record_key, record_value, priority=None):
        """
        Delete a DNS record in AWS Route53
        """
        if record_type == 'MX' and priority:
            record_value = f"{priority} {record_value}"
            
        return route53_client.delete_dns_record(record_type, record_key, record_value)

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
        self.delete_dns_record('MX', self.domain_name, f'inbound-smtp.{AWS_REGION}.amazonaws.com', 10)

        # Remove mail-from records
        mail_from_domain = f'mail.{self.domain_name}'
        self.delete_dns_record('MX', mail_from_domain, f'feedback-smtp.{AWS_REGION}.amazonses.com', 10)
        self.delete_dns_record('TXT', mail_from_domain, f'"v=spf1 include:amazonses.com ~all"')

        # Remove domain identity in SES
        ses_client.delete_identity(self.domain_name)

        return True 