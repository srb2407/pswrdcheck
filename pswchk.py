import requests
import hashlib
import sys


def req_api_data(hash):
    url = 'https://api.pwnedpasswords.com/range/' + hash
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'error fetching : {res.status_code},please check your api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    head, tail = sha1pwd[:5], sha1pwd[5:]
    response = req_api_data(head)
    return get_password_leaks_count(response, tail)


def main(args):
    for pwd in args:
        count = pwned_api_check(pwd)
        if count:
            print(f'{pwd} was found {count} times!!!')
        else:
            print('not found')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
