import requests
from relay.config import LOCKER_API_RELAY_DESTINATION
from relay.utils import b64_lookup_key, get_message_id_bytes, derive_reply_keys, encrypt_reply_metadata


def get_to_address(relay_address):
    """
    Connect to the Locker API to get the corresponding to_address with relay_address
    """
    try:
        r = requests.get(LOCKER_API_RELAY_DESTINATION + relay_address).json()
        return r['destination']
    except (requests.exceptions.ConnectionError, KeyError):
        return None


def get_reply_record_from_lookup_key(lookup_key):
    lookup = b64_lookup_key(lookup_key)

    # TODO
    # Request to API and get Reply record by lookup_key
    return None


def store_reply_record(mail, ses_response):
    # After relaying email, store a Reply record for it
    reply_metadata = {}
    for header in mail["headers"]:
        if header["name"].lower() in ["message-id", "from", "reply-to", "to"]:
            reply_metadata[header["name"].lower()] = header["value"]
    message_id_bytes = get_message_id_bytes(ses_response["MessageId"])
    lookup_key, encryption_key = derive_reply_keys(message_id_bytes)
    lookup = b64_lookup_key(lookup_key)
    encrypted_metadata = encrypt_reply_metadata(encryption_key, reply_metadata)
    payload = {"lookup": lookup, "encrypted_metadata": encrypted_metadata}

    # TODO
    # Request to API to store payload
    return mail


def reply_allowed(from_address, to_address):
    """
    We allow the user to reply an email if:
        - this user is a premium user, or
        - this user is replying to a premium user
    """

    # TODO
    # send request to API to check whether from_address or to_address is premium
    return True
