import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QSpacerItem, QSizePolicy
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
import subprocess
import psutil
import pyshark
import time

class BLE(QWidget):
    def __init__(self):
        super().__init__()
        
        # Настройка интерфейса
        self.initUI()

    def initUI(self):
        self.setWindowTitle("BLE Secure")
        self.setGeometry(100, 100, 400, 300)

        # Установка фона
        self.setStyleSheet("background-color:rgb(21, 44, 68);")  # Третий оттенок синего

        # Создание вертикального Layout
        layout = QVBoxLayout()

        # Установка шрифта
        font = QFont("Rostic", 12)
        self.setFont(font)

        # Метка статуса с изменением цвета части текста
        self.status_label = QLabel(self)
        self.status_label.setText('<span style="color: white;">Статус соединения: </span>'
                                  '<span style="color: yellow;">-</span>')  # Изменяем цвет только части текста
        self.status_label.setStyleSheet("font-size: 30px;")  # Общий стиль для метки
        self.status_label.setAlignment(Qt.AlignCenter)  # Выравнивание по центру
        layout.addWidget(self.status_label)

        # Добавление Spacer для выравнивания
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Кнопка "Начать"
        self.start_button = QPushButton("Нажмите, чтобы начать", self)
        self.start_button.setStyleSheet("font-size: 30px; background-color:rgb(3, 132, 174); color: white;")
        self.start_button.clicked.connect(self.start_function)
        layout.addWidget(self.start_button)

        # Устанавливаем Layout
        self.setLayout(layout)

    def start_function(self):
        # Скрыть кнопку
        self.start_button.hide()
        subprocess.Popen("sudo tshark -i bluetooth0 -a duration:60 -w pack.pcap", shell=True)
        time.sleep(60)
        # Выполнить булеву функцию
        result = self.boolean()

        # Обновить статус
        if result:
            self.status_label.setText('<span style="color: white;">Статус соединения: </span>'
                                       '<span style="color: green;">Безопасно</span>')  # Изменяем цвет текста
        else:
            self.status_label.setText('<span style="color: white;">Статус соединения: </span>'
                                       '<span style="color: red;">Небезопасно</span>')  # Изменяем цвет текста

    def boolean(): # функция, которая анализирует трафик и определяет ключ шифрования, статус соединения
        connection_status = 0
        security_status = 0
        capture = pyshark.FileCapture('pack.pcap') # переменная, которая хранит трафик открытый через pyshark.FileCapture
        length = -1
        pkt = ''
        for packet in capture: # цикл, определяющий пакет с ключом шифрования
            if 'Long Term Key' in str(packet):
                pkt = packet.bthci_cmd.le_long_term_key.replace(':', '')
                break
        length = len(pkt)
        for packet in capture: # цикл, определяющий статус соединения
            if 'Connect Complete' in str(packet):
                connection_status = 1
                break
        if length == 32: # условие, определяющее безопаснсть соединения
            security_status = 1
        if(connection_status == 1 and security_status == 1):
            return 1
        else:
            return 0


if __name__ == '__main__':
    app = QApplication(sys.argv)
    my_app = BLE()
    my_app.show()
    sys.exit(app.exec_())
