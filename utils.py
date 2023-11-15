import hashlib
import random
import string


def sha256Encryption(data, salt):
    data += salt
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def random_salt():
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(30))
