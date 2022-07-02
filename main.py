from asyncio.windows_events import NULL
import json
import random
import requests

from const import *


def add_destination():
    url = API_URL + 'accounts/f81fe3303f26aa40fa277753169ef66b/email/routing/addresses'
    destination_email = input('Destination address: ')
    data = {'email' : destination_email}
    res = requests.post(url, json.dumps(data), headers=HEADERS)
    return res.json()

def add_custom():
    url = API_URL + 'zones/c5d1b5ab796e431b68071921e92ab7fd/email/routing/rules'
    custom_username = input('Custom username: ')
    corresponding_address = input('Corresponding address: ')
    custom_address = custom_username + '@' + CUSTOM_DOMAIN
    email_matcher = [{'type' : 'literal', 'field' : 'to', 'value' : custom_address}]
    action = [{'type' : 'forward', 'value' : [corresponding_address]}]
    data = {'enable' : True, 'actions' : action, 'matchers' : email_matcher}
    res = requests.post(url, json.dumps(data), headers=HEADERS)
    return res.json()

def check_if_verified():
    try:
        address_amount_limit = int(input('Maximum amount of addresses to receive: '))
    except:
        address_amount_limit = NULL

    default_url = API_URL + 'accounts/f81fe3303f26aa40fa277753169ef66b/email/routing/addresses'
    # url with limitation
    # url = API_URL + 'accounts/f81fe3303f26aa40fa277753169ef66b/email/routing/addresses?limit=1000000'


def get_pairs_of_addresses():
    url = API_URL + 'zones/c5d1b5ab796e431b68071921e92ab7fd/email/routing/rules'
    address_to_check = input('Destination address to check: ')
    res = requests.get(url, headers=HEADERS)
    print(res.json())



def main():
    initial_msg = 'Input the method:\n' +\
                    '1. Add destination address.\n' +\
                    '2. Add custom address corresponding to the destination address.\n'+\
                    '3. Check if a destination address is verified.\n' +\
                    '4. Get all the custom address.\n'

    choice = input(initial_msg)
    match choice[0]:
        case '1': 
            print(add_destination())
        case '2': 
            print(add_custom())
        case '3': 
            print(check_if_verified())
        case '4': 
            print(get_pairs_of_addresses())
        case _:
            exit


if __name__ == '__main__':
    main()