from maily.services import AWS
from maily.logger import logger
from maily.config import AWS_ROUTE53_HOSTED_ZONE_ID
from botocore.exceptions import ClientError


class Route53(AWS):
    def __init__(self):
        super().__init__()
        self.service = 'route53'

    @staticmethod
    def _build_change_batch(action, record_type, record_name, record_value, ttl, priority):
        """Construct change batch payload for Route53."""
        if record_type == 'MX':
            record_value = f"{int(priority)} {record_value}"

        return {
            'Changes': [
                {
                    'Action': action,
                    'ResourceRecordSet': {
                        'Name': record_name,
                        'Type': record_type,
                        'TTL': ttl,
                        'ResourceRecords': [{'Value': record_value}]
                    }
                }
            ]
        }

    def _change_record(self, action, record_type, record_name, record_value, ttl, priority):
        """Generic method to change a DNS record in Route53."""
        try:
            change_batch = self._build_change_batch(action, record_type, record_name, record_value, ttl, priority)
            response = self.client.change_resource_record_sets(
                HostedZoneId=AWS_ROUTE53_HOSTED_ZONE_ID,
                ChangeBatch=change_batch
            )
            logger.info(f"[+] {action} record {record_type} {record_name} {record_value} in Route53")
            return response
        except ClientError as e:
            if 'but it was not found' in str(e):
                return
            logger.error(f"[!] Failed to {action.lower()} record in Route53: {e}")

    def create_dns_record(self, record_type, record_name, record_value, ttl=60, priority=10):
        """Create or upsert a DNS record."""
        return self._change_record('UPSERT', record_type, record_name, record_value, ttl, priority)

    def delete_dns_record(self, record_type, record_name, record_value, ttl=60, priority=10):
        """Delete a DNS record."""
        return self._change_record('DELETE', record_type, record_name, record_value, ttl, priority)


route53_client = Route53()
