import requests
from const import *
from secrets import token_hex


def add_destination(email):
    url = f'{CF_ROOT_API}/accounts/{CF_ACCOUNT_ID}/email/routing/addresses'
    payload = {'email': email}
    res = requests.post(url, json=payload, headers=HEADERS)
    return res.json()


def add_mask(mask, destination):
    url = f'{CF_ROOT_API}/zones/{CF_ZONE_ID}/email/routing/rules'
    custom_address = f'{mask}@{CUSTOM_DOMAIN}'
    payload = {
        'enable': True,
        'actions': [{
            'type': 'forward',
            'value': [destination]
        }],
        'matchers': [{
            'type': 'literal',
            'field': 'to',
            'value': custom_address
        }]
    }
    res = requests.post(url, json=payload, headers=HEADERS)
    return res.json()


def get_destinations():
    url = f'{CF_ROOT_API}/accounts/{CF_ACCOUNT_ID}/email/routing/addresses'
    page = 1
    destinations = list()
    while True:
        params = {'page': page}
        r = requests.get(url, headers=HEADERS, params=params)
        result = r.json()['result']
        if len(result) == 0:
            break
        else:
            page += 1
            destinations.extend(result)
    return destinations


if __name__ == '__main__':
    # add_destination('me@trungnh.com')
    # for i in range(1000):
    #     add_destination(f'{token_hex(6)}@trungnh.com')
    # add_mask(token_hex(6), 'me@trungnh.com')
    get_destinations()
