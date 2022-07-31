import requests
from relay.utils import b64_lookup_key
from relay.config import LOCKER_API_RELAY_DESTINATION


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
