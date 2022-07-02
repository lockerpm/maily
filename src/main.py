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
        params = {'page': page, 'per_page': 50}
        r = requests.get(url, headers=HEADERS, params=params)
        result = r.json()['result']
        if len(result) == 0:
            break
        else:
            page += 1
            destinations.extend(result)
    return destinations


def get_destination_tag(email):
    url = f'{CF_ROOT_API}/accounts/{CF_ACCOUNT_ID}/email/routing/addresses'
    page = 1
    while True:
        params = {'page': page, 'per_page': 50}
        r = requests.get(url, headers=HEADERS, params=params)
        result = r.json()['result']
        for r in result:
            if r['email'] == email:
                return r['tag']
        if len(result) == 0:
            return None
        else:
            page += 1


def delete_destination(email):
    tag = get_destination_tag(email)
    url = f'{CF_ROOT_API}/accounts/{CF_ACCOUNT_ID}/email/routing/addresses/{tag}'
    r = requests.delete(url, headers=HEADERS)
    return r.json()


def delete_all_destinations():
    destinations = get_destinations()
    for d in destinations:
        url = f'{CF_ROOT_API}/accounts/{CF_ACCOUNT_ID}/email/routing/addresses/{d["tag"]}'
        r = requests.delete(url, headers=HEADERS)
        print(f'Deleting destination {d["email"]}')
    return True


if __name__ == '__main__':
    # add_destination('me@trungnh.com')
    # for i in range(1000):
    #     add_destination(f'{token_hex(6)}@trungnh.com')
    # add_mask(token_hex(6), 'me@trungnh.com')
    # get_destinations()
    # x = get_destination_tag('me@trungnh.com')
    # x = delete_destination('107@trungnh.com')
    # print(x)
    delete_all_destinations()
