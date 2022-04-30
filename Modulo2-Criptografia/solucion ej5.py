from secrets import token_bytes, randbits
from base64 import b64encode
from Crypto.Hash import SHA1
from time import time
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import jwt



class AuthServer:
    def __init__(self):
        # inicializar datos del servidor (secreto para JWT)
        self._secret = b64encode(token_bytes(4)).decode() # generar secreto
        print(self._secret)
        # inicializar usuarios (diccionario vacio)
        self._users = {}
        print(self._users)

    def register(self, user, password):
        # Guarda los datos necesarios para verificar un login en self._users
        h = SHA1.new()
        h.update(bytes(password, 'ASCII'))
        pw_hash = h.hexdigest()
        salt = get_random_bytes(16)
        pw_hash2 = PBKDF2(password, salt, 64, count=10000, hmac_hash_module=SHA512)
        print(pw_hash2)
        user_store = (pw_hash)
        self._users[user] = (user_store)
        return

    def login(self, user, password):
        # Verifica que el password es correcto para el usuario a partir de los datos guardados en register.
        (stored_pw) = self._users[user]
        h = SHA1.new()
        h.update(bytes(password, 'ASCII'))
        derived_pw = h.hexdigest()
        # Si el password es correcto, devuelve un jwt con el usuario (sub) y la expiracion (exp) en el payload
        if derived_pw == stored_pw:
            expiration = int(time()) + (60*60*6)
            return jwt.encode({'sub': user, 'exp': expiration}, self._secret, algorithm='HS256')
            
        else:
            raise Exception("Bad login")

    def verify(self, token):
        # Verifica el JWT, y si es valido devuelve el usuario 'sub' del payload
        payload = jwt.decode(token, self._secret, algorithms=['HS256', 'None'])
        print(payload)
        return payload['sub']

def client():
    authServer = AuthServer()

    authServer.register("user", "password")
    print(authServer)

    # Realizamos el proceso de login correctamente
    print('> login con credenciales correctas')
    try:
        token = authServer.login("user", "password")
        authenticatedUser = authServer.verify(token)
        if authenticatedUser == "user":
            print('authenticated user: ' + authenticatedUser + ' ✅')
        else:
            print('❌')
    except Exception as e:
        print(e, '❌')

    # Realizamos un login con credenciales incorrectas
    print('> login con credenciales incorrectas')
    try:
        token = authServer.login("user", "1234")
        print('❌')
    except Exception as e:
        print(e, '✅')

    # Enviamos un jwt modificado
    print('> jwt modificado')
    try:
        token = authServer.login("user", "password")
        authenticatedUser = authServer.verify(b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxNTk4NDU0NjEzfQ.pvFFedY2ByyhXAR_pAXkg6FCmzo81e__fpGB-W77k5M')
        print('authenticated user: ' + authenticatedUser + ' ❌')
    except Exception as e:
        print(e, '✅')

client()