import time
import requests
from maily.logger import logger
from maily.config import LOCKER_TOKEN_API
from maily.utils import b64_lookup_key, get_message_id_bytes, derive_reply_keys, encrypt_reply_metadata

ROOT_API = 'https://api.locker.io/v3/cystack_platform/relay/'
HEADERS = {
    "Authorization": f"Token {LOCKER_TOKEN_API}"
}


def get_to_address(relay_address):
    """
    Connect to the Locker API to get the corresponding to_address with relay_address
    """
    # The alias length must be greater than 5
    if len(relay_address.split('@')[0]) < 6:
        return None
    url = f'{ROOT_API}destination?relay_address={relay_address}'
    retry = 1
    while retry <= 3:
        try:
            r = requests.get(url, headers=HEADERS, timeout=10).json()
            return r['destination']
        except KeyError:
            return None
        except:
            logger.info('[!] Could not get the relay address since requesting to Locker API unsuccessfully')
            time.sleep(10)
            retry += 1
    # logger.error(f'[!] Could not get to_address of #{relay_address} since requesting to Locker API unsuccessfully')
    return None


def get_reply_record_from_lookup_key(lookup_key):
    lookup = b64_lookup_key(lookup_key)
    url = f'{ROOT_API}reply?lookup={lookup}'
    try:
        r = requests.get(url, headers=HEADERS, timeout=10).json()
        if r.get('encrypted_metadata') is not None:
            return r
    except:
        return None
    return None


def store_reply_record(mail, ses_response):
    # After relaying email, store a Reply record for it
    reply_metadata = dict()
    for header in mail["headers"]:
        if header["name"].lower() in ["message-id", "from", "reply-to", "to"]:
            reply_metadata[header["name"].lower()] = header["value"]
    message_id_bytes = get_message_id_bytes(ses_response["MessageId"])
    lookup_key, encryption_key = derive_reply_keys(message_id_bytes)
    lookup = b64_lookup_key(lookup_key)
    encrypted_metadata = encrypt_reply_metadata(encryption_key, reply_metadata)
    payload = {"lookup": lookup, "encrypted_metadata": encrypted_metadata}
    # Request to API to store payload
    url = f'{ROOT_API}reply'
    # Handle store reply record failed
    retry = 0
    while retry <= 5:
        try:
            requests.post(url=url, json=payload, headers=HEADERS, timeout=10)
            return True
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout, requests.exceptions.Timeout,
                KeyError):
            time.sleep(10)
            retry += 1
    return False

def reply_allowed(from_address, to_address):
    """
    We allow the user to reply an email if:
        - this user is a premium user, or
        - this user is replying to a premium user
    """

    # send request to API to check whether from_address or to_address is premium
    return check_user_premium(from_address) or check_user_premium(to_address)


def check_user_premium(email):
    """
    Check a user email is premium account or not
    """
    url = f'{ROOT_API}plan?email={email}'
    try:
        r = requests.get(url, headers=HEADERS, timeout=10).json()
        return r["is_premium"]
    except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout, requests.exceptions.Timeout,
            KeyError):
        return False


def get_relay_address_plan(relay_address):
    """
    Connect to the Locker API to retrieve the account plan
    Response data:
        - is_premium: (bool) The account is premium or not
        - enabled: (bool) This relay address is enabled or not
        - block_spam: (bool) This relay address turns on/off block spam feature
    """
    url = f'{ROOT_API}plan?relay_address={relay_address}'
    try:
        r = requests.get(url, headers=HEADERS, timeout=10).json()
        return r
    except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout, requests.exceptions.Timeout,
            KeyError):
        return {}


def send_statistic_relay_address(relay_address, statistic_type):
    """
    Sending statistic number of the relay address to the Locker API
    """
    url = f'{ROOT_API}statistics'
    assert statistic_type in ["forwarded", "block_spam"]
    data_send = {"relay_address": relay_address, "type": statistic_type}
    try:
        r = requests.post(url, headers=HEADERS, json=data_send, timeout=10)
        if r.status_code >= 400:
            return False
        return True
    except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout, requests.exceptions.Timeout,
            KeyError):
        return False
