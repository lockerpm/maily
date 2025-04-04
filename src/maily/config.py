import os

# General
SLACK_WEB_HOOK = os.getenv('SLACK_WEB_HOOK')
RELAY_DOMAIN = "maily.org"
REPLY_EMAIL = f"replies@{RELAY_DOMAIN}"
RELAY_FROM_ADDRESS = f"relay@{RELAY_DOMAIN}"
LOCKER_TOKEN_API = os.getenv('LOCKER_TOKEN_API')

# AWS
AWS_REGION = os.getenv('AWS_REGION')

# SES
AWS_SES_CONFIG_SET = os.getenv('AWS_SES_CONFIG_SET')

# SNS
AWS_SNS_TOPIC = os.getenv('AWS_SNS_TOPIC')
SUPPORTED_SNS_TYPES = [
    "SubscriptionConfirmation",
    "Notification",
]

# Queue
AWS_SQS_URL = os.getenv('AWS_SQS_URL')
PROCESS_EMAIL_BATCH_SIZE = 10
PROCESS_EMAIL_VISIBILITY_SECONDS = 120
PROCESS_EMAIL_WAIT_SECONDS = 5
PROCESS_EMAIL_DELETE_FAILED_MESSAGES = False

# Domain Identity
CF_ZONE = os.getenv('CF_ZONE')
CF_TOKEN = os.getenv('CF_TOKEN')
CF_HEADERS = {'Authorization': f'Bearer {CF_TOKEN}'}
CF_API = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE}/dns_records'

# AWS Route53
AWS_ROUTE53_HOSTED_ZONE_ID = os.getenv('AWS_ROUTE53_HOSTED_ZONE_ID')
