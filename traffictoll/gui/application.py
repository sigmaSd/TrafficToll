import sys

from PyQt5.Qt import QApplication

from traffictoll import __version__
from traffictoll.gui.mainwindow import MainWindow

APPLICATION_NAME = 'TrafficToll'


def start():
    application = QApplication(sys.argv)
    application.setApplicationName(APPLICATION_NAME)
    application.setApplicationDisplayName(APPLICATION_NAME)
    application.setDesktopFileName(APPLICATION_NAME)
    application.setApplicationVersion(__version__)

    window = MainWindow()
    window.show()

    application.exec()
