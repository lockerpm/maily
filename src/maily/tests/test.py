import json

from maily.aws.sqs import sqs_client
from maily.domain_identity import DomainIdentity
from maily.route53_domain_identity import Route53DomainIdentity

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

x = Route53DomainIdentity('manh123.manhtx.site')
# x.create_domain()
x.create_domain()
