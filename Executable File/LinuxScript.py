#!/usr/bin/env python3

import os
import subprocess
import sys
import time
from datetime import datetime

# -------------------------------
# Colors & Print Helpers
# -------------------------------
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(60)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.END}")

# -------------------------------
# Command Execution Helpers
# -------------------------------
def wait_for_dpkg():
    while os.path.exists("/var/lib/dpkg/lock-frontend") or os.path.exists("/var/lib/dpkg/lock"):
        print_warning("dpkg/apt is locked, waiting 2s...")
        time.sleep(2)

def run_command(cmd, description="", ask=True, noninteractive=False):
    if ask:
        print(f"\n{Colors.BOLD}Task:{Colors.END} {description}")
        print(f"{Colors.BOLD}Command:{Colors.END} {cmd}")
        response = input("Execute? (y/n/skip): ").lower()
        if response == 'skip':
            return None
        elif response != 'y':
            return False
    
    if noninteractive and ("apt" in cmd or "dpkg" in cmd):
        cmd = f"DEBIAN_FRONTEND=noninteractive {cmd}"

    wait_for_dpkg()

    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end="")
        process.wait()
        if process.returncode == 0:
            if description:
                print_success(f"Completed: {description}")
            return True
        else:
            if description:
                print_error(f"Failed: {description}")
            return False
    except Exception as e:
        print_error(f"Exception running command: {e}")
        return False

def safe_apt_install(packages, description="Install packages"):
    if isinstance(packages, list):
        packages = " ".join(packages)
    return run_command(f"apt-get install -y {packages}", description, ask=False, noninteractive=True)

def safe_apt_update_upgrade():
    run_command("apt-get update", "Update package lists", ask=False, noninteractive=True)
    run_command("apt-get upgrade -y", "Upgrade installed packages", ask=False, noninteractive=True)
    run_command("apt-get dist-upgrade -y", "Perform distribution upgrade", ask=False, noninteractive=True)
    run_command("apt-get autoremove -y", "Remove unnecessary packages", ask=False, noninteractive=True)

# -------------------------------
# Root Check
# -------------------------------
def check_root():
    if os.geteuid() != 0:
        print_error("This script must be run with sudo privileges!")
        print("Usage: sudo python3 cyberpatriot_linux.py")
        sys.exit(1)

# -------------------------------
# System Info & Updates
# -------------------------------
def system_info():
    print_header("SYSTEM INFORMATION")
    run_command("lsb_release -a", "Display distribution info", ask=False)
    run_command("whoami", "Current user", ask=False)
    run_command("uname -r", "Kernel version", ask=False)

def system_updates():
    print_header("SYSTEM UPDATES")
    safe_apt_update_upgrade()
    print("\nChecking for Shellshock vulnerability...")
    run_command("env x='() { :;}; echo vulnerable' bash -c 'echo Shellshock test'", "Test Shellshock", ask=False)

# -------------------------------
# Automatic Updates
# -------------------------------
def configure_automatic_updates():
    print_header("AUTOMATIC UPDATES")
    safe_apt_install("unattended-upgrades", "Install unattended-upgrades")
    run_command("dpkg-reconfigure -plow unattended-upgrades", "Configure automatic updates")
    print("\nVerify Software & Updates settings manually if needed...")

# -------------------------------
# Security Tools
# -------------------------------
def install_security_tools():
    print_header("SECURITY TOOLS INSTALLATION")
    
    safe_apt_install(["clamav", "clamav-daemon", "clamtk"], "Install ClamAV")
    run_command("systemctl stop clamav-freshclam", "Stop freshclam temporarily", ask=False)
    run_command("freshclam", "Update virus definitions")
    run_command("systemctl start clamav-freshclam", "Start freshclam", ask=False)
    
    # Auditd
    if input("\nInstall auditd for system monitoring? (y/n): ").lower() == 'y':
        safe_apt_install("auditd", "Install auditd")
        run_command("auditctl -e 1", "Enable auditd")
        run_command("systemctl enable auditd", "Enable auditd on boot", ask=False)
    
    # Fail2ban
    if input("\nInstall fail2ban for intrusion prevention? (y/n): ").lower() == 'y':
        safe_apt_install("fail2ban", "Install fail2ban")
        run_command("cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local", "Create jail.local", ask=False)
        run_command("systemctl enable fail2ban", "Enable fail2ban", ask=False)
        run_command("systemctl start fail2ban", "Start fail2ban", ask=False)
    
    # AppArmor
    if input("\nInstall/configure AppArmor? (y/n): ").lower() == 'y':
        safe_apt_install(["apparmor", "apparmor-profiles", "apparmor-utils"], "Install AppArmor")
        run_command("systemctl enable apparmor", "Enable AppArmor", ask=False)
        run_command("aa-enforce /etc/apparmor.d/*", "Enforce AppArmor profiles")

# -------------------------------
# Firewall
# -------------------------------
def configure_firewall():
    print_header("FIREWALL (UFW)")
    safe_apt_install(["ufw", "gufw"], "Install UFW and GUI")
    run_command("ufw default deny incoming", "Deny incoming connections by default")
    run_command("ufw default allow outgoing", "Allow outgoing connections")
    
    if input("Allow SSH? (y/n): ").lower() == 'y':
        run_command("ufw allow ssh", "Allow SSH", ask=False)
    
    services = input("Other services to allow (e.g., http https) or press Enter: ").split()
    for service in services:
        run_command(f"ufw allow {service}", f"Allow {service}", ask=False)
    
    suspicious_ports = ["1337", "31337", "12345", "54321"]
    for port in suspicious_ports:
        run_command(f"ufw deny {port}", f"Deny port {port}", ask=False)
    
    run_command("ufw enable", "Enable firewall")
    run_command("ufw status verbose", "Show firewall status", ask=False)

# -------------------------------
# User Management
# -------------------------------
def manage_users():
    print_header("USER MANAGEMENT")
    run_command("awk -F: '($3>=1000)&&($1!=\"nobody\"){print $1}' /etc/passwd", "List regular users", ask=False)
    run_command("getent group sudo", "Show sudo group members", ask=False)
    run_command("ls -la /etc/sudoers.d", "List sudoers.d files", ask=False)
    
    while True:
        print("\nUser Management Tasks:\n1.Change password\n2.Change all passwords\n3.Delete user\n4.Add user\n5.Manage sudo\n6.Lock account\n7.Check UID0\n8.Check hidden\n9.Lock root\nq.Quit")
        choice = input("Select task: ")
        if choice == 'q':
            break
        elif choice == '1':
            user = input("Username: ")
            run_command(f"passwd {user}", f"Change password for {user}")
        elif choice == '2':
            new_pass = input("New password: ")
            if input("Continue? (yes/no): ").lower() == 'yes':
                cmd = f"for user in $(awk -F: '$3 >= 1000 {{print $1}}' /etc/passwd); do echo \"$user:{new_pass}\" | chpasswd; echo \"Changed $user\"; done"
                run_command(cmd, "Change all user passwords", ask=False)
        elif choice == '3':
            user = input("Username to delete: ")
            run_command(f"userdel -r {user}", f"Delete user {user}")
        elif choice == '4':
            user = input("Username to add: ")
            groups = input("Groups to add user to (comma separated, or leave blank): ")
            cmd = f"useradd -m {user}"
            if groups:
                cmd += f" -G {groups}"
            run_command(cmd, f"Add user {user}")
            run_command(f"passwd {user}", f"Set password for {user}")
        elif choice == '5':
            user = input("Username: ")
            action = input("Add to sudo (a) / remove (r)? ")
            if action == 'a':
                run_command(f"usermod -aG sudo {user}", f"Add {user} to sudo")
            elif action == 'r':
                run_command(f"deluser {user} sudo", f"Remove {user} from sudo")
        elif choice == '6':
            user = input("Username to lock: ")
            run_command(f"passwd -l {user}", f"Lock user {user}")
        elif choice == '7':
            run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd", "Check UID 0 users", ask=False)
        elif choice == '8':
            run_command("cat /etc/passwd | grep -v 'nologin' | grep -v 'false' | awk -F: '{print $1, $3, $6, $7}'", "List users with shells", ask=False)
        elif choice == '9':
            if input("Lock root account? (y/n): ").lower() == 'y':
                run_command("passwd -l root", "Lock root account")

# -------------------------------
# Password Policies
# -------------------------------
def password_policies():
    print_header("PASSWORD POLICIES")
    safe_apt_install(["libpam-pwquality", "libpam-cracklib"], "Install password quality libraries")
    if input("Apply password quality? (y/n): ").lower() == 'y':
        run_command("cp /etc/pam.d/common-password /etc/pam.d/common-password.bak", "Backup common-password", ask=False)
        run_command("sed -i 's/\\(pam_unix\\.so.*\\)$/\\1 remember=5 minlen=12/' /etc/pam.d/common-password", "Set password history and min length", ask=False)
        run_command("sed -i 's/\\(pam_cracklib\\.so.*\\)$/\\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password", "Set complexity", ask=False)

    if input("Apply password aging? (y/n): ").lower() == 'y':
        run_command("cp /etc/login.defs /etc/login.defs.bak", "Backup login.defs", ask=False)
        run_command("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   30/' /etc/login.defs", "Set max days", ask=False)
        run_command("sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs", "Set min days", ask=False)
        run_command("sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   12/' /etc/login.defs", "Set warn age", ask=False)

# -------------------------------
# Guest/Autologin
# -------------------------------
def disable_guest_and_autologin():
    print_header("GUEST & AUTOLOGIN")
    lightdm_configs = ["/etc/lightdm/lightdm.conf","/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"]
    for config in lightdm_configs:
        if os.path.exists(config):
            run_command(f"sed -i 's/^autologin-user=.*/autologin-user=none/' {config}", "Disable autologin user", ask=False)
            run_command(f"sed -i 's/^autologin-guest=.*/autologin-guest=false/' {config}", "Disable autologin guest", ask=False)
            run_command(f"sed -i 's/^greeter-hide-users=.*/greeter-hide-users=true/' {config}", "Hide greeter users", ask=False)
            run_command(f"sed -i 's/^greeter-show-manual-login=.*/greeter-show-manual-login=true/' {config}", "Show manual login", ask=False)

# -------------------------------
# Kernel & System Hardening
# -------------------------------
def kernel_hardening():
    print_header("KERNEL & SYSCTL HARDENING")
    sysctl_settings = {
        "fs.file-max": "65535",
        "fs.protected_fifos": "2",
        "fs.protected_regular": "2",
        "fs.suid_dumpable": "0",
        "kernel.core_uses_pid": "1",
        "kernel.dmesg_restrict": "1",
        "kernel.exec-shield": "1",
        "kernel.sysrq": "0",
        "kernel.randomize_va_space": "2",
        "net.ipv4.ip_forward": "0",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv6.conf.all.disable_ipv6": "1"
    }
    for k,v in sysctl_settings.items():
        run_command(f"sysctl -w {k}={v}", f"Set {k}={v}", ask=False)
    run_command("sysctl -p", "Reload sysctl settings", ask=False)

# -------------------------------
# Forensics Helpers
# -------------------------------
def forensics_helpers():
    print_header("FORENSICS & FILE AUDIT HELPERS")
    run_command("ls -la /home", "List all home directories with permissions", ask=False)
    run_command("find / -type f -name '*.mp3'", "Find media files (*.mp3)", ask=False)
    run_command("locate *.mp3", "Locate media files", ask=False)
    run_command("dpkg --list | grep -E 'telnet|ftp|vsftpd|rsh|rlogin|nfs|samba|apache|bind9'", "Check for unauthorized packages", ask=False)

# -------------------------------
# Main Menu
# -------------------------------
def main_menu():
    while True:
        print_header("CYBERPATRIOT LINUX SECURITY - EXPANDED ADVANCED")
        print("0.System Info 1.System Updates 2.Automatic Updates 3.Security Tools 4.Firewall 5.User Mgmt 6.Password Policies 7.Disable Guest/AutoLogin 8.Kernel Hardening 9.Forensics 99.Exit")
        choice = input("Select option: ").strip()
        if choice == '0': system_info()
        elif choice == '1': system_updates()
        elif choice == '2': configure_automatic_updates()
        elif choice == '3': install_security_tools()
        elif choice == '4': configure_firewall()
        elif choice == '5': manage_users()
        elif choice == '6': password_policies()
        elif choice == '7': disable_guest_and_autologin()
        elif choice == '8': kernel_hardening()
        elif choice == '9': forensics_helpers()
        elif choice == '99':
            print("\n" + Colors.GREEN + "Exiting. Good luck in the competition!" + Colors.END)
            break
        else:
            print_error("Invalid option!")
        input("Press Enter to continue...")

# -------------------------------
# Script Entry
# -------------------------------
if __name__ == "__main__":
    try:
        check_root()
        main_menu()
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        sys.exit(1)
