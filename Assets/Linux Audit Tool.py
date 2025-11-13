# gui/main_gui.py
import os, sys
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6 import uic, QtWidgets
from PyQt6.QtCore import QProcess, QTimer

version_state = {
    "version" : 1.0-1,
    "Developed by" : "LordTael125"
}

class AuditApp(QtWidgets.QMainWindow):
    def __init__(self, ui_file):
        super().__init__()
        uic.loadUi(ui_file, self)

        self.runningStaus = False
        

        self.runButton = self.findChild(QtWidgets.QPushButton, "runButton")
        self.outputBox = self.findChild(QtWidgets.QTextEdit, "outputBox")
        self.progressBar = self.findChild(QtWidgets.QProgressBar, "progressBar")
        self.statusLabel = self.findChild(QtWidgets.QLabel, "statusLabel")

        self.closeButton = self.findChild(QtWidgets.QPushButton,"closeButton")
        self.helpButton = self.findChild(QtWidgets.QPushButton,"helpButton")

        self.closeButton.clicked.connect(self.close_app)
        self.helpButton.clicked.connect(self.helpDialog)
        self.runButton.clicked.connect(self.run_audit)

    def run_audit(self):
        self.runningStaus = True
        self.runButton.setEnabled(False)
        self.outputBox.clear()
        self.progressBar.setValue(0)
        self.statusLabel.setText("Running...")

        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self.read_output)
        self.process.readyReadStandardError.connect(self.read_output)
        self.process.finished.connect(self.finish_audit)

        BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        audit_script_path = os.path.join(BASE_DIR, "core", "Audit_core.py")
        # audit_script_path = os.path.abspath(os.path.join("Audit_core.py"))
        self.process.start("pkexec", ["python3", audit_script_path])

    def read_output(self):
        output = bytes(self.process.readAllStandardOutput()).decode("utf-8")
        self.outputBox.append(output)
        if "Firewall check Completed" in output:
            self.progressBar.setValue(20)
        elif "SSH config files scanned" in output:
            self.progressBar.setValue(40)
        elif "File Permission checked" in output:
            self.progressBar.setValue(60)
        elif "Services Scanned Successfully" in output:
            self.progressBar.setValue(80)
        elif "Audit complete" in output:
            self.progressBar.setValue(100)

    def show_popup(self,title,message,time=1000):
        msg = QMessageBox()
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setStandardButtons(QMessageBox.StandardButton.NoButton)
        msg.show()
        QTimer.singleShot(time, msg.accept)  # Close after 1 second
        return msg

    def finish_audit(self):
        self.runningStaus = False
        self.runButton.setEnabled(True)
        self.statusLabel.setText("Completed")

    def helpDialog(self):
        QMessageBox.information(
            self,
            "Help Dialog Window",
            "This is a linux audit evalution program\n"
            "This program will evaluate your system security\n"
            "Press Run Audit Button to start evaluation"
        )

    def close_app(self) :
        if self.runningStaus :
            QMessageBox.information(
                self,
                "Wait for Process",
                "The scanning is going under\n"
                "Wait for Process to complete"
            )
        else :
            title = "Closing application"
            message = "Closing Application\nThe application is shutting down \n...."
            popup = self.show_popup(title,message)
            popup.exec()
            QApplication.exit()
            
    


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    
    BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    UI_PATH = os.path.join(BASE_DIR, "Interface.ui")

    window = AuditApp(UI_PATH)

    window.show()
    sys.exit(app.exec())
