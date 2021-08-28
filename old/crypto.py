from database import PasswordDatabase
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import json
from base64 import b64encode, b64decode #test
from Crypto.Cipher import AES
import re


class Crypto(PasswordDatabase):
    def __init__(self):
        PasswordDatabase.__init__(self)

    def encrypt_db(self):
        db = [('bobbie', 'bobbie@dickhead.com', 'dickhead', 'dickhead.com'), ('ya mum', 'yamum@fuckoff.com', 'banana?', 'facebook.com')]
        master_password = 'e'

        with open("passwords.txt", "w") as file:
            for i in range(len(db)):
                current_tuple = list(db[i])
                current_tuple = tuple(current_tuple)
                plaintext = ",".join(current_tuple)

                salt = get_random_bytes(16)
                key = PBKDF2(master_password, salt, 16, count=1000000, hmac_hash_module=SHA512)

                file.write(f"salt={b64encode(salt)},")

                header = b"Password Number" + str(i).encode()
                cipher = AES.new(key, AES.MODE_GCM)
                cipher.update(header)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

                json_k = ['nonce', 'header', 'ciphertext', 'tag']
                json_v = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag)]
                result = json.dumps(dict(zip(json_k, json_v)))

                print(result, "\n")
                file.write(result + "\n")

    def decrypt_db(self):
        with open("passwords.txt", "r") as file:
            master_password = "e"

            for line in file:
                stripped_line = line.strip()
                ssalt = re.findall('''salt=b'(.*)',''', str(stripped_line))
                salt = b64decode(ssalt[0])

                key = PBKDF2(master_password, salt, 16, count=1000000, hmac_hash_module=SHA512)

                json_input = re.findall("salt=b'.*',({.*})", str(stripped_line))
                b64 = json.loads(json_input[0])
                json_k = ['nonce', 'header', 'ciphertext', 'tag']
                jv = {k: b64decode(b64[k]) for k in json_k}

                cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
                cipher.update(jv['header'])
                plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])

                plaintext = tuple(plaintext.decode().strip().split(","))
                print(plaintext)


if __name__ == "__main__":
    crypto = Crypto()
    crypto.encrypt_db()
    crypto.decrypt_db()
