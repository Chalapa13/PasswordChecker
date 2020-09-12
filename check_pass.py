import requests
import hashlib
import sys


def request_api_data(partial_hash):
    url = 'https://api.pwnedpasswords.com/range/' + str(partial_hash)
    response = requests.request(method='get', url=url)

    # Check if we the request was successful and if not raise an error
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the API and retry.')

    return response


def get_leak_count(response, remainder):
    '''

    :param response: Got from the API call
    :param remainder: What was left after spliting the hash, compare this to the hashes
    received in order to olny retrieve the one corresponding to our checked pass
    :return: The amount of times the checked pass has been leaked
    '''

    content = str(response.text)

    # Grab the corresponding hash for our initial pass
    # by checking the remainder of the hex digest
    for line in content.splitlines():
        key, leaks = line.split(":")[0], line.split(":")[1]

        if str.upper(key) == str.upper(remainder):
            return int(leaks)

    return 0


def pwned_api_check(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest()
    partial_hash, remainder = sha1pass[:5], sha1pass[5:]
    response = request_api_data(partial_hash=partial_hash)

    leak_count = get_leak_count(response, remainder)

    if leak_count > 0:
        print(f'Password with hash \'{password}\' has been leaked {leak_count} times.')
    else:
        print(f'No leaks have been found for password with hash \'{password}\'.')


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        print(arg)
        pwned_api_check(str(arg))
