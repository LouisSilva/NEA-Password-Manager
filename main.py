import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QMainWindow


class PasswordManagerGui(QMainWindow):
    def __init__(self):
        super(PasswordManagerGui, self).__init__()
        loadUi("PasswordManagerGui.ui", self)
        self.pushButtonAdd.clicked.connect(self.__openDialogAdd)


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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = QtWidgets.QStackedWidget()

    password_manager_gui = PasswordManagerGui()

    widget.addWidget(password_manager_gui)
    widget.show()

    try:
        sys.exit(app.exec_())
    except Exception as e:
        print(e)