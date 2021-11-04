import requests
import hashlib
import sys

def api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200 :
        raise RuntimeError(f'Error fetching data: {response.status_code}, Check the api and try again.')
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hash, count in hashes:
        if hash == hash_to_check:
            return count
    return 0


def api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    sha1_password_first5 = sha1_password[:5]
    sha1_password_tail = sha1_password[5:]
    response = api_data(sha1_password_first5)
    print(response)
    return get_password_leaks_count(response, sha1_password_tail)


def main(args):
    for password in args:
        count = api_check(password)
        if count:
            return(f'{password} was found {count} times... you should consider changing your password')
        else:
            return(f'{password} was not found. your password has not been pawned and it is secure.')
        

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))