import argparse
import hashlib

from Crypto.Cipher import AES


def _decrypt(key, block):
    enc = AES.new(key, AES.MODE_ECB)
    dec = AES.new(key, AES.MODE_ECB)

    tweak = enc.encrypt(bytes(16))

    temp = bytes(a ^ b for a, b in zip(block, tweak))
    plaintext = bytes(a ^ b for a, b in zip(dec.decrypt(temp), tweak))

    return plaintext


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('dbfile', type=str)
    parser.add_argument('password', type=str)

    # TODO encoding?

    args = parser.parse_args()

    with open(args.dbfile, 'rb') as f:
        f.seek(10); salt = f.read(8)
        f.seek(4096); ct = f.read(16)

    for label, pwd in [('UTF-16BE', args.password.encode('utf-16-be')), 
                       ('UTF-8', args.password.encode('utf-8'))]:
        key = hashlib.pbkdf2_hmac('sha256', pwd, salt, 10, dklen=16)
        z = _decrypt(key, ct)
        print(label.ljust(12), z)

