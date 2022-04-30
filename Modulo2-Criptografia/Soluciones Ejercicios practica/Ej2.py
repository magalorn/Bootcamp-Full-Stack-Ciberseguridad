from Crypto import Random
from Crypto.Cipher import AES
from Block.ctr import aes_ctr
from OTP.xor import xor_data
from secrets import token_bytes, randbits

class SuperSafeServer:
    def __init__(self):
        self._key = token_bytes(AES.key_size[0])
        self._nonce = randbits(64)

    def create_cookie(self, user_data):
        if b';' in user_data or b'=' in user_data:
            raise Exception("Caracteres ilegales en user data")
        cookie_string = b"cookieversion=2.0;userdata=" + user_data + b";safety=veryhigh"
        return aes_ctr(cookie_string, self._key, self._nonce)

    def check_admin(self, cookie):
        cookie_string = aes_ctr(cookie, self._key, self._nonce)
        return b';admin=true;' in cookie_string


def forge_cookie():
    server = SuperSafeServer()
    user_data = b"?admin?true"
    cookie = server.create_cookie(user_data)

    goal_text = b';admin=true'
    insert = xor_data(user_data, goal_text)

    prefix_length = len(b"cookieversion=2.0;userdata=")

    forged_cookie = cookie[:prefix_length] + \
                    xor_data(cookie[prefix_length:prefix_length + len(user_data)], insert) + \
                    cookie[prefix_length + len(user_data):]

    if server.check_admin(forged_cookie):
        print("Acceso Admin!")
    else:
        print("Acceso denegado")