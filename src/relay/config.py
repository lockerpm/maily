import os

AWS_SNS_TOPIC = "arn:aws:sns:us-east-1:574819034706:locker-relay"
SUPPORTED_SNS_TYPES = [
    "SubscriptionConfirmation",
    "Notification",
]
SLACK_WEB_HOOK = os.getenv('SLACK_WEB_HOOK')
AWS_REGION = "us-east-1"
RELAY_DOMAIN = "xoso.dev"
SITE_ORIGIN = "http://127.0.0.1:8000"
RELAY_FROM_ADDRESS = "relay@xoso.dev"
AWS_SES_CONFIG_SET = "locker_relay"

# SNS
AWS_SNS_KEY_CACHE = "default"

# Queue
SQS_URL = 'https://sqs.us-east-1.amazonaws.com/574819034706/locker-relay'
PROCESS_EMAIL_BATCH_SIZE = 10
PROCESS_EMAIL_VISIBILITY_SECONDS = 120
PROCESS_EMAIL_WAIT_SECONDS = 5
PROCESS_EMAIL_DELETE_FAILED_MESSAGES = False
