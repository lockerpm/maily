import os
import re
import json
import base64
import jwcrypto.jwe
import jwcrypto.jwk
from email.header import Header
from email.utils import parseaddr
from email.headerregistry import Address
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from django.template.defaultfilters import linebreaksbr, urlize
from relay.config import RELAY_FROM_ADDRESS, RELAY_DOMAINS
from relay.logger import logger
from tempfile import SpooledTemporaryFile
from relay import ROOT_PATH
from jinja2 import Template


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
    # "[via Relay] <relay_from>" and encode it all.
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


def encrypt_reply_metadata(key, payload):
    """Encrypt the given payload into a JWE, using the given key."""
    # This is a bit dumb, we have to base64-encode the key in order to load it :-/
    k = jwcrypto.jwk.JWK(
        kty="oct", k=base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")
    )
    e = jwcrypto.jwe.JWE(
        json.dumps(payload), json.dumps({"alg": "dir", "enc": "A256GCM"}), recipient=k
    )
    return e.serialize(compact=True)


def decrypt_reply_metadata(key, jwe):
    """Decrypt the given JWE into a json payload, using the given key."""
    # This is a bit dumb, we have to base64-encode the key in order to load it :-/
    k = jwcrypto.jwk.JWK(
        kty="oct", k=base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")
    )
    e = jwcrypto.jwe.JWE()
    e.deserialize(jwe)
    e.decrypt(k)
    return e.plaintext


def extract_email_from_string(email_string):
    match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', email_string)
    return match.group(0)


def get_recipient_with_relay_domain(recipients):
    for recipient in recipients:
        for domain in RELAY_DOMAINS:
            if domain in recipient:
                return recipient
    return None


def get_attachment(part):
    fn = part.get_filename()
    payload = part.get_payload(decode=True)
    attachment = SpooledTemporaryFile(
        max_size=150 * 1000, prefix="relay_attachment_"  # 150KB max from SES
    )
    attachment.write(payload)
    return fn, attachment


def get_all_contents_email(email_message):
    text_content = None
    html_content = None
    attachments = []
    if email_message.is_multipart():
        for part in email_message.walk():
            try:
                if part.is_attachment():
                    att_name, att = get_attachment(part)
                    attachments.append((att_name, att))
                    continue
                if part.get_content_type() == "text/plain":
                    text_content = part.get_content()
                if part.get_content_type() == "text/html":
                    html_content = part.get_content()
            except KeyError:
                # log the un-handled content type but don't stop processing
                logger.error(f"part.get_content(). type:{part.get_content_type()}")
        if text_content is not None and html_content is None:
            html_content = urlize_and_linebreaks(text_content)
    else:
        if email_message.get_content_type() == "text/plain":
            text_content = email_message.get_content()
            html_content = urlize_and_linebreaks(email_message.get_content())
        if email_message.get_content_type() == "text/html":
            html_content = email_message.get_content()

    # TODO: if html_content is still None, wrap the text_content with our
    # header and footer HTML and send that as the html_content
    return text_content, html_content, attachments


def wrap_html_email(original_html):
    """
    Add Relay banners, surveys, etc. to an HTML email
    """
    email_context = {
        "original_html": original_html
    }
    template_path = os.path.join(ROOT_PATH, "templates", "wrapped_email.html")
    return Template(open(template_path, encoding="utf-8").read()).render(email_context)


def get_verdict(receipt, verdict_type):
    return receipt["%sVerdict" % verdict_type]["status"]
