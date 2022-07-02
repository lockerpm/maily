import json
import requests
from const import *
from secrets import token_hex


def add_destination(email):
    url = f'{CF_ROOT_API}/accounts/{CF_ACCOUNT_ID}/email/routing/addresses'
    payload = {'email': email}
    res = requests.post(url, json=payload, headers=HEADERS)
    print(res.json())
    return res.json()


def add_mask(mask, destination):
    url = f'{CF_ROOT_API}/zones/{CF_ZONE_ID}/email/routing/rules'
    custom_address = f'{mask}@{CUSTOM_DOMAIN}'
    email_matcher = [{'type': 'literal', 'field': 'to', 'value': custom_address}]
    action = [{'type': 'forward', 'value': [destination]}]
    data = {'enable': True, 'actions': action, 'matchers': email_matcher}
    res = requests.post(url, json=data, headers=HEADERS)
    print(res.json())


def check_if_verified():
    try:
        address_amount_limit = int(input('Maximum amount of addresses to receive: '))
    except:
        address_amount_limit = NULL

    default_url = CF_ROOT_API + 'accounts/f81fe3303f26aa40fa277753169ef66b/email/routing/addresses'
    # url with limitation
    # url = API_URL + 'accounts/f81fe3303f26aa40fa277753169ef66b/email/routing/addresses?limit=1000000'


def get_pairs_of_addresses():
    url = CF_ROOT_API + 'zones/c5d1b5ab796e431b68071921e92ab7fd/email/routing/rules'
    address_to_check = input('Destination address to check: ')
    res = requests.get(url, headers=HEADERS)
    print(res.json())


if __name__ == '__main__':
    # add_destination('me@trungnh.com')
    # for i in range(1000):
    #     add_destination(f'{token_hex(6)}@trungnh.com')
    add_mask(token_hex(6), 'me@trungnh.com')

    # url = CF_ROOT_API + 'zones/c5d1b5ab796e431b68071921e92ab7fd/email/routing/rules'
    # custom_username = token_hex(6)
    # # corresponding_address = input('Corresponding address: ')
    # custom_address = custom_username + '@' + CUSTOM_DOMAIN
    # email_matcher = [{'type' : 'literal', 'field' : 'to', 'value' : custom_address}]
    # action = [{'type' : 'forward', 'value' : ['me@trungnh.com']}]
    # data = {'enable' : True, 'actions' : action, 'matchers' : email_matcher}
    # res = requests.post(url, json.dumps(data), headers=HEADERS)
    # print(res.json())
