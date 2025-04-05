import json

from maily.services.sqs import sqs_client
from maily.domain_identity import DomainIdentity

# action_msg = {
#     'action': 'create',
#     'domain': 'manh1.manhtx.org'
# }
#
# msg = {
#     'Type': 'DomainIdentity',
#     'Message': json.dumps(action_msg)
# }
# sqs_client.send_message(json.dumps(msg))

x = DomainIdentity('trungnh.manhtx.site')
# x.create_domain()
y = x.delete_domain()
# print(y)
