import sys
import sqlite3
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QMainWindow
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
import re


class PasswordManager(QMainWindow):
    def __init__(self):
        super(PasswordManager, self).__init__()
        loadUi("PasswordManagerGui.ui", self)
        self.pushButtonAdd.clicked.connect(self.__openDialogAdd)

        self.conn = sqlite3.connect(":memory:")
        self.curs = self.conn.cursor()
        self.curs.execute("""CREATE TABLE IF NOT EXISTS passwords (
                                                                     ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                                                                     Username TEXT,
                                                                     Email TEXT,
                                                                     Password TEXT NOT NULL,
                                                                     App TEXT NOT NULL
                                                                 );""")

    def __openDialogAdd(self):
        # widget.setCurrentIndex(widget.currentIndex()+1)
        self.dialogAdd = loadUi("dialogAdd.ui")
        self.dialogAdd.pushButtonClear.clicked.connect(self.__clearRow)
        self.dialogAdd.exec()

    def __clearRow(self):
        self.dialogAdd.lineEditUsernameInsert.clear()
        self.dialogAdd.lineEditEmailInsert.clear()
        self.dialogAdd.lineEditPasswordInsert.clear()
        self.dialogAdd.lineEditAppInsert.clear()

    def encrypt_db(self):
        db = self.get_database()
        master_password = 'password'

        with open("passwords.txt", "w") as file:
            for i in range(len(db)):
                current_tuple = list(db[i])
                del current_tuple[0]
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
        records = []
        with open("passwords.txt", "r") as file:
            master_password = "password"

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
                records.append(plaintext)

        return records


class WelcomeScreen(QDialog):
    def __init__(self):
        super(WelcomeScreen, self).__init__()
        loadUi("welcome_screen.ui", self)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = QtWidgets.QStackedWidget()

    welcome = WelcomeScreen()
    # password_manager_gui = PasswordManager()
    # password_manager_gui.decrypt_db()
    # widget.addWidget(password_manager_gui)
    widget.addWidget(welcome)

    widget.setFixedWidth(1200)
    widget.setFixedHeight(800)

    widget.show()

    try:
        sys.exit(app.exec_())
    except Exception as e:
        print(e)