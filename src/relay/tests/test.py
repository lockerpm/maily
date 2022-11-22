import json

from relay.aws.sqs import sqs_client
from relay.domain_identity import DomainIdentity

action_msg = {
    'action': 'create',
    'domain': 'trung5.maily.org'
}

msg = {
    'Type': 'DomainIdentity',
    'Message': json.dumps(action_msg)
}
# sqs_client.send_message(json.dumps(msg))

x = DomainIdentity('maily.org')
x.create_domain()
# x.delete_domain()
