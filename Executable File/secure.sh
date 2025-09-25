#!/bin/bash
# CyberPatriot Linux Hardening Script
# USE WITH CAUTION – review before running!
# Run as root: sudo bash secure.sh

set -e

echo "[+] Updating system..."
apt-get update -y && apt-get upgrade -y && apt-get dist-upgrade -y
apt-get autoremove -y && apt-get autoclean -y

echo "[+] Installing security tools..."
apt-get install -y ufw clamav clamtk chkrootkit rkhunter libpam-cracklib auditd

echo "[+] Configuring firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh

echo "[+] Disabling root SSH login..."
if grep -qF 'PermitRootLogin' /etc/ssh/sshd_config; then
    sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config
else
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
fi
systemctl restart ssh || service ssh restart

echo "[+] Locking root account..."
passwd -l root

echo "[+] Securing login.defs..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

echo "[+] Securing /etc/shadow..."
chmod 640 /etc/shadow

echo "[+] Removing dangerous software..."
apt-get -y purge telnet vsftpd* samba* apache2* nginx* netcat-traditional hydra* john* nikto* ophcrack*

echo "[+] Enforcing PAM password policy..."
# Adds strong password requirements
sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n/' /etc/pam.d/common-password
sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5/' /etc/pam.d/common-password

echo "[+] Enforcing account lockout after 5 failures..."
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    sed -i '1i auth required pam_faillock.so preauth silent deny=5 unlock_time=1800' /etc/pam.d/common-auth
    sed -i '2i auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800' /etc/pam.d/common-auth
fi

echo "[+] Securing sysctl..."
cat <<EOF >> /etc/sysctl.conf

# CyberPatriot hardening
net.ipv4.ip_forward=0
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
sysctl -p

echo "[+] Changing all non-system user passwords..."
NEW_PASSWORD="Cyb3rPatr!0t$"
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    echo "$user:$NEW_PASSWORD" | chpasswd
    echo "Password reset for $user"
done

echo "[+] Checking for unauthorized sudo users..."
getent group sudo

echo "[+] Removing common media files..."
for suffix in mp3 mp4 wav wma aac avi mov; do
    find /home -name "*.$suffix" -type f -delete
done

echo "[+] Running rootkit/malware scans..."
chkrootkit -q || true
rkhunter --update && rkhunter --propupd && rkhunter -c --enable all --disable none || true
freshclam && clamscan -r --bell -i /home || true

echo "[+] Hardening complete. Review logs and test logins!"
