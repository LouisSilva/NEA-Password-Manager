import sys
import string
import random
import sqlite3
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QDialog, QApplication, QMainWindow, QFileDialog, QMessageBox
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
        self.pushButtonCreateNewPasswordDatabase.clicked.connect(self.gotoCreateNewPasswordDatabase)
        # Loads the welcome screen gui and connects the login and create password database buttons to the functions

    def gotoLogin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex() + 1)
        # Changes the screen to the login gui

    def gotoCreateNewPasswordDatabase(self):
        createDB = CreateDatabase()
        widget.addWidget(createDB)
        widget.setCurrentIndex(widget.currentIndex() + 1)
        # Changes the screen to the create new password databse gui


class CreateDatabase(QDialog):
    def __init__(self):
        super(CreateDatabase, self).__init__()
        loadUi("dialogCreateNewPasswordDatabase.ui", self)

        # self.lineEditMasterPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pushButtonCreate.clicked.connect(self.create)
        self.pushButtonSelectPasswordDatabaseLocation.clicked.connect(self.select_password_db_location)

        self.master_password = None
        self.password_db_location = None
        # Loads in the create new password database gui and connects the create and select password database buttons to the functions

    def gotoPasswordManager(self):
        password_manager = PasswordManager("[]", self.master_password, self.password_db_location)
        widget.addWidget(password_manager)
        widget.setCurrentIndex(widget.currentIndex() + 1)
        # Changes the screen to the password manager gui

    def select_password_db_location(self):
        directory = str(QtWidgets.QFileDialog.getExistingDirectory())
        file = directory + "/passwords.txt"
        self.lineEditPasswordDatabaseLocation.setText(file)
        # Open the file browser window and let the user select a location for the new password database

    def create(self):
        self.master_password = self.lineEditMasterPassword.text()
        self.password_db_location = str(self.lineEditPasswordDatabaseLocation.text())
        db = []
        # Take user input for the master password and the new database location.
        try:
            with open(self.password_db_location, "w") as file:
                for i in range(len(db)):
                    current_tuple = list(db[i])
                    current_tuple = tuple(current_tuple)
                    plaintext = ",".join(current_tuple)
                    # Create the new password database text file

                    salt = get_random_bytes(16)
                    key = PBKDF2(self.master_password, salt, 16, count=1000000, hmac_hash_module=SHA512)
                    # Create a salt and key

                    file.write(f"salt={b64encode(salt)},")
                    # Encode the salt with base64

                    header = b"Password Number" + str(i).encode()
                    cipher = AES.new(key, AES.MODE_GCM)
                    cipher.update(header)
                    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
                    # Create the header and cipher text

                    json_k = ['nonce', 'header', 'ciphertext', 'tag']
                    json_v = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag)]
                    result = json.dumps(dict(zip(json_k, json_v)))
                    # Combine the cipher text, nonce, tag and header into a single array and write it to the text file

            self.gotoPasswordManager()
            # Open the password manager screen

        except FileNotFoundError:
            warningBox = QMessageBox()
            warningBox.setIcon(QMessageBox.Critical)
            warningBox.setText("You need to enter a valid file path")
            warningBox.setWindowTitle("Warning")
            warningBox.setStandardButtons(QMessageBox.Ok)
            warningBox.exec_()
            # This creates a warning box if the user didn't input a valid file path


class LoginScreen(QDialog):
    def __init__(self):
        super(LoginScreen, self).__init__()
        loadUi("login.ui", self)

        self.lineEditMasterPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pushButtonLogin.clicked.connect(self.decrypt_db)
        self.pushButtonChangePasswordDatabaseLocation.clicked.connect(self.change_password_database_location)
        # Connect the login button and change password database location button to the fucntions

        self.records = []
        self.master_password = None
        self.password_db_location = None
        # Create variables

    def gotoPasswordManager(self):
        password_manager = PasswordManager(self.records, self.master_password, self.password_db_location)
        widget.addWidget(password_manager)
        widget.setCurrentIndex(widget.currentIndex() + 1)
        # Go to password manager screen

    def change_password_database_location(self):
        file_name = QFileDialog.getOpenFileName(self, 'Open Password Database File', r"C:", "Text files (*.txt)")
        self.lineEditPasswordDatabaseLocation.setText(file_name[0])
        # Open file browser and let the user find the password database in windows explorer

    def decrypt_db(self):
        self.master_password = self.lineEditMasterPassword.text()
        self.password_db_location = self.lineEditPasswordDatabaseLocation.text()
        # Get master password and password db location from user input

        if len(self.master_password) == 0:
            self.labelError.setText("Please input a master password")
            # If the master password box is empty, prompt the user to enter a password.

        elif len(self.password_db_location) == 0:
            self.labelError.setText("Please input the file location for the password db")
            # If the password box is empty, prompt the user to enter the location

        else:
            try:
                with open(self.password_db_location, "r") as file:
                    for line in file:
                        stripped_line = line.strip()
                        ssalt = re.findall('''salt=b'(.*)',''', str(stripped_line))
                        salt = b64decode(ssalt[0])
                        # Open the password db file, get the salt and decode it from base64

                        key = PBKDF2(self.master_password, salt, 16, count=1000000, hmac_hash_module=SHA512)
                        # Create the key from the salt and master password

                        json_input = re.findall("salt=b'.*',({.*})", str(stripped_line))
                        b64 = json.loads(json_input[0])
                        json_k = ['nonce', 'header', 'ciphertext', 'tag']
                        jv = {k: b64decode(b64[k]) for k in json_k}
                        # Get the ciphertext, nonce, header and tag

                        cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
                        cipher.update(jv['header'])
                        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
                        # Create the cipher and check if the ciphertext has been tampered with. If it hasn't, decrypt

                        plaintext = tuple(plaintext.decode().strip().split(","))
                        self.records.append(plaintext)
                        # Put each record into a tuple, and add each tuple to an array.

                    self.gotoPasswordManager()

            except ValueError:
                warningBox = QMessageBox()
                warningBox.setIcon(QMessageBox.Critical)
                warningBox.setText("The password is invalid. Please try again")
                warningBox.setWindowTitle("Warning")
                warningBox.setStandardButtons(QMessageBox.Ok)
                warningBox.exec_()
                # This creates a warning box if the user didn't input the correct password

            except FileNotFoundError:
                warningBox = QMessageBox()
                warningBox.setIcon(QMessageBox.Critical)
                warningBox.setText("You need to enter a valid file path")
                warningBox.setWindowTitle("Warning")
                warningBox.setStandardButtons(QMessageBox.Ok)
                warningBox.exec_()
                # This creates a warning box if the user didn't input a valid file path


class PasswordManager(QDialog):
    def __init__(self, records, master_password, db_location):
        super(PasswordManager, self).__init__()
        loadUi("PasswordManagerGuiNew.ui", self)

        widget.setFixedWidth(1271)
        widget.setFixedHeight(861)

        self.tableWidgetPasswords.setColumnWidth(0, 307)
        self.tableWidgetPasswords.setColumnWidth(1, 307)
        self.tableWidgetPasswords.setColumnWidth(2, 307)
        self.tableWidgetPasswords.setColumnWidth(3, 307)

        self.pushButtonAdd.clicked.connect(self.open_DialogAdd)
        self.pushButtonDelete.clicked.connect(self.open_DialogDelete)
        self.pushButtonSearch.clicked.connect(self.search)
        self.pushButtonSave.clicked.connect(self.save)
        self.pushButtonPasswordGenerator.clicked.connect(self.open_DialogPasswordGenerator)

        self.records = records
        self.master = master_password
        self.db_location = db_location
        # print(self.records)
        # Load the password manager Ui, and connect all the buttons to the appropriate functions and set the window's width and height

        self.conn = sqlite3.connect(":memory:")
        self.curs = self.conn.cursor()
        self.curs.execute("""CREATE TABLE IF NOT EXISTS passwords (
                                                                     ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                                                                     Username TEXT,
                                                                     Email TEXT,
                                                                     Password TEXT NOT NULL,
                                                                     App TEXT NOT NULL
                                                                 );""")
        # Create the sql database and store it in main memory

        for record in self.records:
            try:
                self.curs.execute(f"""INSERT INTO passwords
                                            VALUES (NULL, ?, ?, ?, ?)""", record)
                self.conn.commit()
            except Exception as e:
                print(e)
        # For each record, insert it into the database

        self.load_data("SELECT * FROM passwords")
        # Get all passwords from the database

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
        # Clear the table and add all the records in

    def search(self):
        keyword = self.lineEditSearchKeywords.text()
        if keyword == "":
            query = "SELECT * FROM passwords"
        else:
            query = f"SELECT * FROM passwords WHERE username='{keyword}' OR email='{keyword}' OR app='{keyword}';"
        self.load_data(query)
        # Get the keyword from user input and use sql query to search for data in the database

    def open_DialogAdd(self):
        self.dialogAdd = loadUi("dialogAdd.ui")
        self.dialogAdd.pushButtonClear.clicked.connect(self.clear_DialogAdd)
        self.dialogAdd.pushButtonAdd.clicked.connect(self.add_record)
        self.dialogAdd.exec()
        # Open the add record ui

    def clear_DialogAdd(self):
        self.dialogAdd.lineEditUsername.clear()
        self.dialogAdd.lineEditEmail.clear()
        self.dialogAdd.lineEditPassword.clear()
        self.dialogAdd.lineEditApp.clear()
        # Clear all of the user input boxes

    def add_record(self):
        if len(self.dialogAdd.lineEditUsername.text()) == 0:
            print("U need to input something in username")
        elif len(self.dialogAdd.lineEditEmail.text()) == 0:
            print("U need to input something in email")
        elif len(self.dialogAdd.lineEditPassword.text()) == 0:
            print("U need to input something in password")
        elif len(self.dialogAdd.lineEditApp.text()) == 0:
            print("U need to input something in app")
        # Check if any of the boxes are empty

        else:
            try:
                self.records = self.records + str(
                    ((self.dialogAdd.lineEditUsername.text(), self.dialogAdd.lineEditEmail.text(),
                      self.dialogAdd.lineEditPassword.text(), self.dialogAdd.lineEditApp.text())))
                self.curs.execute(f"""INSERT INTO passwords
                                            VALUES (NULL, ?, ?, ?, ?)""", (
                    self.dialogAdd.lineEditUsername.text(), self.dialogAdd.lineEditEmail.text(),
                    self.dialogAdd.lineEditPassword.text(), self.dialogAdd.lineEditApp.text()))
                self.conn.commit()
            except Exception as e:
                print(e)
            # Add all of the records into the database

        self.load_data("SELECT * FROM passwords")
        # Load the database with the new data

    def open_DialogDelete(self):
        self.dialogDelete = loadUi("dialogDelete.ui")
        self.dialogDelete.pushButtonDelete.clicked.connect(self.delete_record)

        self.dialogDelete.comboBoxEmail.addItem("...")
        self.dialogDelete.comboBoxApp.addItem("...")
        # Open the delete record ui

        for record in self.curs.execute("SELECT * FROM passwords"):
            self.dialogDelete.comboBoxEmail.addItem(record[2])
            self.dialogDelete.comboBoxApp.addItem(record[4])

        self.dialogDelete.exec()
        # Fill the email and app combo boxes with each record

    def delete_record(self):
        try:
            if self.dialogDelete.comboBoxEmail.currentText() == "...":
                print("You need to select a value for email")
            elif self.dialogDelete.comboBoxApp.currentText() == "...":
                print("You need to select a value for app")
            # Check if any of the two boxes are empty

            else:
                self.curs.execute(
                    f"DELETE FROM passwords WHERE email='{self.dialogDelete.comboBoxEmail.currentText()}' AND app='{self.dialogDelete.comboBoxApp.currentText()}';")
                self.conn.commit()
                self.load_data("SELECT * FROM passwords")

        except Exception as e:
            print(e)
        # Delete all of the records that match the keywords

    def encrypt_db(self):
        self.curs.execute("SELECT * FROM passwords")
        rows = self.curs.fetchall()
        # Get all of the records

        with open(self.db_location, "w") as file:
            for i in range(len(rows)):
                current_tuple = rows[i]
                current_tuple = list(current_tuple)
                del current_tuple[0]
                current_tuple = tuple(current_tuple)
                plaintext = ",".join(current_tuple)
                # Open the password db text file and get all of the records into an array of tuples

                salt = get_random_bytes(16)
                key = PBKDF2(self.master, salt, 16, count=1000000, hmac_hash_module=SHA512)
                # Create a salt and then create an encryption key with the master password and salt

                file.write(f"salt={b64encode(salt)},")
                # Encode the salt with base64 and write it to the text file

                header = b"Password Number" + str(i).encode()
                cipher = AES.new(key, AES.MODE_GCM)
                cipher.update(header)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
                # Create the header and tag and create the cipher

                json_k = ['nonce', 'header', 'ciphertext', 'tag']
                json_v = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag)]
                result = json.dumps(dict(zip(json_k, json_v)))
                # Get the nonce, header, ciphertext and tag into json format

                # print(result, "\n")
                file.write(result + "\n")
                # Write the nonce, header, ciphertext and tag to the file

    def password_generator(self):
        if self.dialogPasswordGenerator.checkBoxNumbers.isChecked() and self.dialogPasswordGenerator.checkBoxSpecialCharacters.isChecked():
            characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")
        elif self.dialogPasswordGenerator.checkBoxNumbers.isChecked():
            characters = list(string.ascii_letters + string.digits)
        elif self.dialogPasswordGenerator.checkBoxSpecialCharacters.isChecked():
            characters = list(string.ascii_letters + "!@#$%^&*()")
        else:
            characters = list(string.ascii_letters)
        # Get the criteria for what the password needs to include and not include

        random.shuffle(characters)
        password_list = []
        for i in range(self.dialogPasswordGenerator.spinBoxLength.value()):
            password_list.append(random.choice(characters))
        # Shuffle the list of characters

        random.shuffle(password_list)
        password = ""

        for i in range(len(password_list)):
            password += password_list[i]
        # Randomly select random characters to make the password

        self.dialogPasswordGenerator.lineEditPassword.setText(password)
        # Display the password to the ui

    def open_DialogPasswordGenerator(self):
        self.dialogPasswordGenerator = loadUi("dialogPasswordGenerator.ui")
        self.dialogPasswordGenerator.pushButtonGenerate.clicked.connect(self.password_generator)
        self.dialogPasswordGenerator.exec()
        # Open the password generator ui

    def save(self):
        self.hide()
        self.encrypt_db()
        sys.exit()
        # The save and close function, 1). Hide the window, 2). Encrypt the database and 3). Exit the program


if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = QtWidgets.QStackedWidget()
    # Run the ui window and create the stacked widget class

    welcome = WelcomeScreen()
    widget.addWidget(welcome)

    widget.setFixedWidth(1149)
    widget.setFixedHeight(889)
    # Open the window screen and set the fixed width and height

    widget.show()
    widget.setWindowTitle("Password Manager")
    widget.setWindowIcon(QtGui.QIcon("lock.ico"))
    # Show the welcome screen with the title and icon

    sys.exit(app.exec_())
    # Close the program


