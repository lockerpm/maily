import requests

from maily.config import *
from maily.logger import logger


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


x = create_dns_record('MX', f'*.{RELAY_DOMAIN}', f'inbound-smtp.{AWS_REGION}.amazonaws.com', 10)
print(x.text)
x = create_dns_record('MX', f'*.{RELAY_DOMAIN}', f'feedback-smtp.{AWS_REGION}.amazonses.com', 10)
print(x.text)
x = create_dns_record('TXT', f'*.{RELAY_DOMAIN}', '"v=spf1 include:amazonses.com ~all"')
print(x.text)
