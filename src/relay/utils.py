import base64
from email.header import Header
from email.utils import parseaddr
from email.headerregistry import Address
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from django.template.defaultfilters import linebreaksbr, urlize
from relay.config import RELAY_FROM_ADDRESS


def get_message_id_bytes(message_id_str):
    message_id = message_id_str.split("@", 1)[0].rsplit("<", 1)[-1].strip()
    return message_id.encode()


def b64_lookup_key(lookup_key):
    return base64.urlsafe_b64encode(lookup_key).decode("ascii")


def derive_reply_keys(message_id):
    """Derive the lookup key and encryption key from an aliased message id."""
    algorithm = hashes.SHA256()
    hkdf = HKDFExpand(algorithm=algorithm, length=16, info=b"replay replies lookup key")
    lookup_key = hkdf.derive(message_id)
    hkdf = HKDFExpand(
        algorithm=algorithm, length=32, info=b"replay replies encryption key"
    )
    encryption_key = hkdf.derive(message_id)
    return lookup_key, encryption_key


def urlize_and_linebreaks(text, auto_escape=True):
    return linebreaksbr(urlize(text, autoescape=auto_escape), autoescape=auto_escape)


def generate_relay_from(original_from_address):
    _, relay_from_address = parseaddr(RELAY_FROM_ADDRESS)
    # RFC 2822 (https://tools.ietf.org/html/rfc2822#section-2.1.1)
    # says email header lines must not be more than 998 chars long.
    # Encoding display names to longer than 998 chars will add wrap
    # characters which are unsafe. (See https://bugs.python.org/issue39073)
    # So, truncate the original sender to 900 chars so we can add our
    # "[via Relay] <relayfrom>" and encode it all.
    if len(original_from_address) > 998:
        original_from_address = "%s ..." % original_from_address[:900]
    # line breaks in From: will encode to unsafe chars, so strip them.
    original_from_address = (
        original_from_address.replace("\u2028", "").replace("\r", "").replace("\n", "")
    )

    display_name = Header('"%s [via Relay]"' % original_from_address, "UTF-8")
    formatted_from_address = str(
        Address(display_name.encode(maxlinelen=998), addr_spec=relay_from_address)
    )
    return formatted_from_address
