from botocore.exceptions import ClientError

from maily.aws import AWS
from maily.logger import logger
from maily.config import AWS_ROUTE53_HOSTED_ZONE_ID


class Route53(AWS):
    def __init__(self):
        super().__init__()
        self.service = 'route53'

    def create_dns_record(self, record_type, record_name, record_value, ttl=300):
        """
        Create DNS records in AWS Route53
        
        Args:
            record_type: Record type (A, CNAME, MX, TXT, etc.)
            record_name: Record name (domain or subdomain)
            record_value: Record value
            ttl: Time to live in seconds (default: 300)
            
        Returns:
            Response from Route53 API
        """
        try:
            change_batch = {
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': record_name,
                            'Type': record_type,
                            'TTL': ttl,
                            'ResourceRecords': [
                                {
                                    'Value': record_value
                                }
                            ]
                        }
                    }
                ]
            }
            
            # Handle MX records that require priority
            if record_type == 'MX':
                # Extract priority from the beginning of the value if it exists
                if ' ' in record_value and record_value.split(' ')[0].isdigit():
                    priority, mx_value = record_value.split(' ', 1)
                    change_batch['Changes'][0]['ResourceRecordSet']['ResourceRecords'][0]['Value'] = f"{priority} {mx_value}"
                else:
                    # Default priority 10 if not specified
                    change_batch['Changes'][0]['ResourceRecordSet']['ResourceRecords'][0]['Value'] = f"10 {record_value}"
                    
            response = self.client.change_resource_record_sets(
                HostedZoneId=AWS_ROUTE53_HOSTED_ZONE_ID,
                ChangeBatch=change_batch
            )
            
            logger.info(f'[+] Created record {record_type} {record_name} {record_value} in Route53')
            return response
            
        except ClientError as e:
            logger.error(f'[!] Failed to create record in Route53: {e}')
            return None

    def delete_dns_record(self, record_type, record_name, record_value, ttl=300):
        """
        Delete DNS records in AWS Route53
        
        Args:
            record_type: Record type (A, CNAME, MX, TXT, etc.)
            record_name: Record name (domain or subdomain)
            record_value: Record value
            ttl: Time to live in seconds (default: 300)
            
        Returns:
            Response from Route53 API
        """
        try:
            change_batch = {
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': record_name,
                            'Type': record_type,
                            'TTL': ttl,
                            'ResourceRecords': [
                                {
                                    'Value': record_value
                                }
                            ]
                        }
                    }
                ]
            }
            
            # Handle MX records that require priority
            if record_type == 'MX':
                # Extract priority from the beginning of the value if it exists
                if ' ' in record_value and record_value.split(' ')[0].isdigit():
                    priority, mx_value = record_value.split(' ', 1)
                    change_batch['Changes'][0]['ResourceRecordSet']['ResourceRecords'][0]['Value'] = f"{priority} {mx_value}"
                else:
                    # Default priority 10 if not specified
                    change_batch['Changes'][0]['ResourceRecordSet']['ResourceRecords'][0]['Value'] = f"10 {record_value}"

            response = self.client.change_resource_record_sets(
                HostedZoneId=AWS_ROUTE53_HOSTED_ZONE_ID,
                ChangeBatch=change_batch
            )
            
            logger.info(f'[+] Deleted record {record_type} {record_name} {record_value} from Route53')
            return response
            
        except ClientError as e:
            logger.error(f'[!] Failed to delete record from Route53: {e}')
            return None


# Initialize Route53 client
route53_client = Route53() 