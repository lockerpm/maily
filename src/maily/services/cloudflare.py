import time
import requests
from maily.config import *
from maily.logger import logger


class Cloudflare:
    @staticmethod
    def create_dns_record(record_type, record_name, record_value, ttl=300, priority=10):
        """
        Create DNS records in Cloudflare
        """
        payload = {"type": record_type, "name": record_name, "content": record_value}
        if record_type == 'MX':
            payload["priority"] = priority

        retry = 0
        while retry <= 5:
            try:
                r = requests.post(CF_API, headers=CF_HEADERS, json=payload)
                if r.status_code >= 500:
                    logger.warning(f'[+] Created record 5xx {record_type} {record_name} {record_value} => '
                                   f'{r.status_code} - {r.text}')
                    retry += 1
                    time.sleep(1)
                    continue
                else:
                    logger.info(f'[+] Created record {record_type} {record_name} {record_value} => '
                                f'{r.status_code} - {r.text}')
                    return r
            except (requests.exceptions.RequestException, requests.exceptions.ConnectTimeout):
                retry += 1
                time.sleep(1)
        logger.error(f'[+] Created DNS record error {record_type} {record_name} {record_value}')

    @staticmethod
    def delete_dns_record(record_type, record_name, record_value, ttl=300, priority=10):
        """
        Delete a DNS record in Cloudflare
        """
        url = f'{CF_API}?type={record_type}&name={record_name}&content={record_value}&page=1&per_page=100&match=all'
        r = requests.get(url, headers=CF_HEADERS)
        for record in r.json()['result']:
            url = f'{CF_API}/{record["id"]}'
            retry = 0
            while retry <= 5:
                try:
                    r = requests.delete(url, headers=CF_HEADERS)
                    if r.status_code >= 500:
                        logger.warning(f'[+] Delete record 5xx {record_type} {record_name} {record_value} => '
                                       f'{r.status_code} - {r.text}')
                        retry += 1
                        time.sleep(1)
                        continue
                    else:
                        logger.info(f'[+] Deleted record {record_type} {record_name} {record_value} => '
                                    f'{r.status_code} - {r.text}')
                        return
                except (requests.exceptions.RequestException, requests.exceptions.ConnectTimeout):
                    retry += 1
                    time.sleep(1)
            logger.error(f'[+] Deleted DNS record error {record_type} {record_name} {record_value}')

    @staticmethod
    def list_dns_records():
        """
        List all DNS records in Cloudflare
        """
        url = f'{CF_API}?page=1&per_page=2000&match=all'
        r = requests.get(url, headers=CF_HEADERS)
        return r.json()['result']


cf_client = Cloudflare()
