from Crypto import Random
from Crypto.Cipher import AES
from secrets import token_bytes, randbits
from base64 import b64decode
import struct

def xor_data(binary_data_1, binary_data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])


def aes_ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def aes_ctr(data, key, nonce):
    """Encrypts or decrypts with AES-CTR mode."""
    output = b''
    counter = 0
    

    # Takes a block size of input at each time (or less if a block-size is not available), and XORs
    # it with the encrypted concatenation of nonce and counter.
    while data:

        # Get the little endian bytes concatenation of nonce and counter (each 64bit values)
        concatenated_nonce_and_counter = struct.pack('<QQ', nonce, counter)

        # Encrypt the concatenation of nonce and counter
        encrypted_counter = aes_ecb_encrypt(concatenated_nonce_and_counter, key)

        # XOR the encrypted value with the input data
        output += xor_data(encrypted_counter, data[:AES.block_size])
        #print(output)

        # Update data to contain only the values that haven't been encrypted/decrypted yet
        data = data[AES.block_size:] 

        # Update the counter as prescribed in the CTR mode of operation
        counter += 1

    return output


class SuperSafeServer:
    def __init__(self):
        self._key = token_bytes(AES.key_size[0])
        print(self._key)
        self._nonce = randbits(64)
        print(self._nonce)

    def create_cookie(self, user_data):
        if ';' in user_data or '=' in user_data:
            raise Exception("Caracteres ilegales en user data")
        user_data = ""
        cookie_string = "cookieversion=2.0;userdata=" +  user_data + ";safety=veryhigh"
        return aes_ctr(cookie_string.encode(), self._key, self._nonce)

    def check_admin(self, cookie):
        cookie_string = aes_ctr(cookie, self._key, self._nonce).decode()
        return ';admin=true;' in cookie_string


def forge_cookie():
    server = SuperSafeServer()
    user_data = "marcos@gmail.com+admin-true" # Modificar user_data inicial
    # No sé si iría por aqui la solución del ejercicio, pero ya no he conseguido pasar 
    # de este punto
    cookie = server.create_cookie(user_data) 
    print(cookie)
    
    # Modificar la cookie
    if server.check_admin(cookie):
        print("Acceso Admin!")




forge_cookie()

