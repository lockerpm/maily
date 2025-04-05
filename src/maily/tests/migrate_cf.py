from maily.services.cloudflare import cf_client
from maily.services.route53 import route53_client

records = cf_client.list_dns_records()
for r in records:
    record_type = r['type']
    record_name = r['name']
    record_value = r['content']
    priority = r.get('priority', 10)
    route53_client.create_dns_record(record_type, record_name, record_value, ttl=60, priority=priority)
