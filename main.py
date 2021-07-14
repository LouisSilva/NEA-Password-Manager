import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QMainWindow


class PasswordManagerGui(QMainWindow):
    def __init__(self):
        super(PasswordManagerGui, self).__init__()
        loadUi("PasswordManagerGui.ui", self)
        self.pushButtonAdd.clicked.connect(self.openDialogAdd)


    def openDialogAdd(self):
        # widget.setCurrentIndex(widget.currentIndex()+1)
        dialog = loadUi("dialogAdd.ui")
        dialog.exec()


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