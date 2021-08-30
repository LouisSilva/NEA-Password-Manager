import sys
import sqlite3
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QMainWindow, QFileDialog
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
import re


class WelcomeScreen(QDialog):
    def __init__(self):
        super(WelcomeScreen, self).__init__()
        loadUi("welcome_screen.ui", self)
        self.pushButtonLogin.clicked.connect(self.gotoLogin)

    def gotoLogin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex() + 1)


class LoginScreen(QDialog):
    def __init__(self):
        super(LoginScreen, self).__init__()
        loadUi("login.ui", self)

        self.lineEditMasterPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pushButtonLogin.clicked.connect(self.decrypt_db)
        self.pushButtonChangePasswordDatabaseLocation.clicked.connect(self.change_password_database_location)

        self.records = []
        self.master_password = None
        self.password_db_location = None

    def gotoPasswordManager(self):
        password_manager = PasswordManager(self.records)
        widget.addWidget(password_manager)
        widget.setCurrentIndex(widget.currentIndex() + 1)

    def change_password_database_location(self):
        file_name = QFileDialog.getOpenFileName(self, 'Open Password Database File', r"C:", "Text files (*.txt)")
        self.lineEditPasswordDatabaseLocation.setText(file_name[0])

    def decrypt_db(self):
        self.master_password = self.lineEditMasterPassword.text()
        self.password_db_location = self.lineEditPasswordDatabaseLocation.text()

        if len(self.master_password) == 0:
            self.labelError.setText("Please input a master password")

        elif len(self.password_db_location) == 0:
            self.labelError.setText("Please input the file location for the master password")

        else:

            with open(self.password_db_location, "r") as file:
                for line in file:
                    stripped_line = line.strip()
                    ssalt = re.findall('''salt=b'(.*)',''', str(stripped_line))
                    salt = b64decode(ssalt[0])

                    key = PBKDF2(self.master_password, salt, 16, count=1000000, hmac_hash_module=SHA512)

                    json_input = re.findall("salt=b'.*',({.*})", str(stripped_line))
                    b64 = json.loads(json_input[0])
                    json_k = ['nonce', 'header', 'ciphertext', 'tag']
                    jv = {k: b64decode(b64[k]) for k in json_k}

                    cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
                    cipher.update(jv['header'])
                    plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])

                    plaintext = tuple(plaintext.decode().strip().split(","))
                    self.records.append(plaintext)

            self.gotoPasswordManager()


class PasswordManager(QDialog):
    def __init__(self, records):
        super(PasswordManager, self).__init__()
        loadUi("PasswordManagerGuiNew.ui", self)

        widget.setFixedWidth(847)

        self.tableWidgetPasswords.setColumnWidth(0, 203.5)
        self.tableWidgetPasswords.setColumnWidth(1, 203.5)
        self.tableWidgetPasswords.setColumnWidth(2, 203.5)
        self.tableWidgetPasswords.setColumnWidth(3, 204)

        self.pushButtonAdd.clicked.connect(self.openDialogAdd)
        self.pushButtonSearch.clicked.connect(self.search)

        self.records = records
        print(self.records)

        self.conn = sqlite3.connect(":memory:")
        self.curs = self.conn.cursor()
        self.curs.execute("""CREATE TABLE IF NOT EXISTS passwords (
                                                                     ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                                                                     Username TEXT,
                                                                     Email TEXT,
                                                                     Password TEXT NOT NULL,
                                                                     App TEXT NOT NULL
                                                                 );""")

        for record in self.records:
            try:
                self.curs.execute(f"""INSERT INTO passwords
                                            VALUES (NULL, ?, ?, ?, ?)""", record)
                self.conn.commit()
            except Exception as e:
                print(e)

        self.load_data("SELECT * FROM passwords")

    def load_data(self, query):
        self.tableWidgetPasswords.clear()
        self.tableWidgetPasswords.setRowCount(len(self.records))
        row = 0
        for record in self.curs.execute(query):
            self.tableWidgetPasswords.setItem(row, 0, QtWidgets.QTableWidgetItem(record[1]))
            self.tableWidgetPasswords.setItem(row, 1, QtWidgets.QTableWidgetItem(record[2]))
            self.tableWidgetPasswords.setItem(row, 2, QtWidgets.QTableWidgetItem(record[3]))
            self.tableWidgetPasswords.setItem(row, 3, QtWidgets.QTableWidgetItem(record[4]))

            row += 1

        self.tableWidgetPasswords.setRowCount(row)

    def search(self):
        keyword = self.lineEditSearchKeywords.text()
        if keyword == "":
            query = "SELECT * FROM passwords"
        else:
            query = f"SELECT * FROM passwords WHERE username='{keyword}' OR email='{keyword}' OR app='{keyword}';"
        self.load_data(query)

    def openDialogAdd(self):
        # widget.setCurrentIndex(widget.currentIndex()+1)
        self.dialogAdd = loadUi("dialogAdd.ui")
        self.dialogAdd.pushButtonClear.clicked.connect(self.clearRowDialogAdd)
        self.dialogAdd.pushButtonAdd.clicked.connect(self.addRecord)
        self.dialogAdd.exec()

    def clearRowDialogAdd(self):
        self.dialogAdd.lineEditUsername.clear()
        self.dialogAdd.lineEditEmail.clear()
        self.dialogAdd.lineEditPassword.clear()
        self.dialogAdd.lineEditApp.clear()

    def addRecord(self):
        if len(self.dialogAdd.lineEditUsername.text()) == 0: print("U need to input something in username")
        elif len(self.dialogAdd.lineEditEmail.text()) == 0: print("U need to input something in email")
        elif len(self.dialogAdd.lineEditPassword.text()) == 0: print("U need to input something in password")
        elif len(self.dialogAdd.lineEditApp.text()) == 0: print("U need to input something in app")

        else:
            try:
                self.records.append((self.dialogAdd.lineEditUsername.text() + self.dialogAdd.lineEditEmail.text() + self.dialogAdd.lineEditPassword.text() + self.dialogAdd.lineEditApp.text()))
                self.curs.execute(f"""INSERT INTO passwords
                                            VALUES (NULL, ?, ?, ?, ?)""", (self.dialogAdd.lineEditUsername.text(), self.dialogAdd.lineEditEmail.text(), self.dialogAdd.lineEditPassword.text(), self.dialogAdd.lineEditApp.text()))
                self.conn.commit()
            except Exception as e:
                print(e)

        self.load_data("SELECT * FROM passwords")

    def encrypt_db(self):
        db = self.get_database()
        master_password = 'e'

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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = QtWidgets.QStackedWidget()

    welcome = WelcomeScreen()
    widget.addWidget(welcome)

    widget.setFixedWidth(1200)
    widget.setFixedHeight(800)

    widget.show()

    try:
        sys.exit(app.exec_())
    except Exception as e:
        print(e)

# D:/Docs/Work/Home/New/Computer_Science/Programming/Python/Projects/NEA_PasswordManager/Code/Disguisable-Password-Manager/passwords.txt
