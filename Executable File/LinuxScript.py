#!/usr/bin/env python3
"""
CyberPatriot Linux Security Automation Script - ADVANCED EDITION
Comprehensive security hardening for CyberPatriot competitions
"""

import os
import subprocess
import sys
from datetime import datetime

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

def run_command(cmd, description, ask=True):
    """Run a command with user confirmation"""
    if ask:
        print(f"\n{Colors.BOLD}Task:{Colors.END} {description}")
        print(f"{Colors.BOLD}Command:{Colors.END} {cmd}")
        response = input("Execute? (y/n/skip): ").lower()
        if response == 'skip':
            return None
        elif response != 'y':
            return False
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print_success(f"Completed: {description}")
            if result.stdout:
                print(result.stdout)
            return True
        else:
            print_error(f"Failed: {description}")
            if result.stderr:
                print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print_error(f"Exception running command: {e}")
        return False

def check_root():
    """Check if script is running with sudo/root privileges"""
    if os.geteuid() != 0:
        print_error("This script must be run with sudo privileges!")
        print("Usage: sudo python3 cyberpatriot_linux.py")
        sys.exit(1)

def system_info():
    """Display system information"""
    print_header("SYSTEM INFORMATION")
    run_command("lsb_release -a", "Display distribution info", ask=False)
    run_command("whoami", "Current user", ask=False)
    run_command("uname -r", "Kernel version", ask=False)

def system_updates():
    """Handle system updates"""
    print_header("SYSTEM UPDATES")
    run_command("apt-get update", "Update package lists")
    run_command("apt-get upgrade -y", "Upgrade installed packages")
    run_command("apt-get dist-upgrade -y", "Perform distribution upgrade")
    run_command("apt-get autoremove -y", "Remove unnecessary packages")
    
    # Check for Shellshock vulnerability
    print("\n" + Colors.BOLD + "Checking for Shellshock vulnerability..." + Colors.END)
    run_command("env x='() { :;}; echo vulnerable' bash -c 'echo Shellshock test'", "Test Shellshock", ask=False)

def configure_automatic_updates():
    """Configure automatic security updates"""
    print_header("AUTOMATIC UPDATES")
    run_command("apt-get install unattended-upgrades -y", "Install unattended-upgrades")
    run_command("dpkg-reconfigure -plow unattended-upgrades", "Configure automatic updates")
    
    print("\n" + Colors.BOLD + "Verify Software & Updates settings:" + Colors.END)
    print("- Open Software & Updates")
    print("- Check first four checkmarks in Ubuntu Software tab")
    print("- Set 'When there are security updates: Display immediately'")
    print("- Set 'When there are other updates: Display immediately'")

def install_security_tools():
    """Install essential security tools"""
    print_header("SECURITY TOOLS INSTALLATION")
    
    # ClamAV
    run_command("apt-get install clamav clamav-daemon clamtk -y", "Install ClamAV")
    run_command("systemctl stop clamav-freshclam", "Stop freshclam temporarily", ask=False)
    run_command("freshclam", "Update virus definitions")
    run_command("systemctl start clamav-freshclam", "Start freshclam", ask=False)
    
    # Auditd
    if input("\nInstall auditd for system monitoring? (y/n): ").lower() == 'y':
        run_command("apt-get install auditd -y", "Install auditd")
        run_command("auditctl -e 1", "Enable auditd")
        run_command("systemctl enable auditd", "Enable auditd on boot", ask=False)
    
    # Fail2ban
    if input("\nInstall fail2ban for intrusion prevention? (y/n): ").lower() == 'y':
        run_command("apt-get install fail2ban -y", "Install fail2ban")
        run_command("cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local", "Create jail.local", ask=False)
        run_command("systemctl enable fail2ban", "Enable fail2ban", ask=False)
        run_command("systemctl start fail2ban", "Start fail2ban", ask=False)
    
    # AppArmor
    if input("\nInstall/configure AppArmor? (y/n): ").lower() == 'y':
        run_command("apt-get install apparmor apparmor-profiles apparmor-utils -y", "Install AppArmor")
        run_command("systemctl enable apparmor", "Enable AppArmor", ask=False)
        run_command("aa-enforce /etc/apparmor.d/*", "Enforce AppArmor profiles")

def configure_firewall():
    """Configure UFW firewall"""
    print_header("FIREWALL (UFW)")
    run_command("apt-get install ufw gufw -y", "Install UFW and GUI")
    run_command("ufw default deny incoming", "Deny incoming connections by default")
    run_command("ufw default allow outgoing", "Allow outgoing connections")
    
    # Check if SSH is needed
    print("\n" + Colors.BOLD + "Common services:" + Colors.END)
    if input("Allow SSH? (y/n): ").lower() == 'y':
        run_command("ufw allow ssh", "Allow SSH", ask=False)
    
    services = input("Other services to allow (e.g., http https) or press Enter: ").split()
    for service in services:
        run_command(f"ufw allow {service}", f"Allow {service}", ask=False)
    
    # Block suspicious ports
    print("\n" + Colors.BOLD + "Blocking common backdoor ports..." + Colors.END)
    suspicious_ports = ["1337", "31337", "12345", "54321"]
    for port in suspicious_ports:
        run_command(f"ufw deny {port}", f"Deny port {port}", ask=False)
    
    run_command("ufw enable", "Enable firewall")
    run_command("ufw status verbose", "Show firewall status", ask=False)

def manage_users():
    """User and password management"""
    print_header("USER MANAGEMENT")
    
    # List current users
    print(Colors.BOLD + "Current users with login shells:" + Colors.END)
    run_command("awk -F: '($3>=1000)&&($1!=\"nobody\"){print $1}' /etc/passwd", "List regular users", ask=False)
    
    print("\n" + Colors.BOLD + "Admin users (sudo group):" + Colors.END)
    run_command("getent group sudo", "Show sudo group members", ask=False)
    
    print("\n" + Colors.BOLD + "Checking /etc/sudoers.d for unauthorized privileges:" + Colors.END)
    run_command("ls -la /etc/sudoers.d", "List sudoers.d files", ask=False)
    
    print("\n" + Colors.BOLD + "User Management Tasks:" + Colors.END)
    print("1. Change user passwords")
    print("2. Change ALL user passwords (bulk)")
    print("3. Delete unauthorized users")
    print("4. Add missing users")
    print("5. Manage sudo privileges")
    print("6. Lock/disable accounts")
    print("7. Check for UID 0 users (root equivalents)")
    print("8. Check for hidden users")
    print("9. Lock root account")
    
    while True:
        choice = input("\nSelect task (1-9) or 'q' to quit: ")
        if choice == 'q':
            break
        elif choice == '1':
            user = input("Username to change password: ")
            run_command(f"passwd {user}", f"Change password for {user}")
        elif choice == '2':
            new_pass = input("Enter new password for all users: ")
            print_warning("This will change passwords for all non-system users (UID >= 1000)")
            if input("Continue? (yes/no): ").lower() == 'yes':
                cmd = f"for user in $(awk -F: '$3 >= 1000 {{print $1}}' /etc/passwd); do echo \"$user:{new_pass}\" | chpasswd; echo \"Changed password for $user\"; done"
                run_command(cmd, "Change all user passwords", ask=False)
        elif choice == '3':
            user = input("Username to delete: ")
            run_command(f"userdel -r {user}", f"Delete user {user}")
        elif choice == '4':
            user = input("Username to add: ")
            run_command(f"useradd -m {user}", f"Add user {user}")
            run_command(f"passwd {user}", f"Set password for {user}")
        elif choice == '5':
            user = input("Username: ")
            action = input("Add to sudo group (a) or remove (r)? ")
            if action == 'a':
                run_command(f"usermod -aG sudo {user}", f"Add {user} to sudo")
            elif action == 'r':
                run_command(f"deluser {user} sudo", f"Remove {user} from sudo")
        elif choice == '6':
            user = input("Username to lock: ")
            run_command(f"passwd -l {user}", f"Lock user {user}")
        elif choice == '7':
            print("\n" + Colors.BOLD + "Users with UID 0 (should only be root):" + Colors.END)
            run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd", "Check UID 0 users", ask=False)
        elif choice == '8':
            print("\n" + Colors.BOLD + "Checking for hidden/suspicious users:" + Colors.END)
            run_command("cat /etc/passwd | grep -v 'nologin' | grep -v 'false' | awk -F: '{print $1, $3, $6, $7}'", "List users with shells", ask=False)
            run_command("ls -la /home", "Check home directories", ask=False)
        elif choice == '9':
            if input("Lock root account? (y/n): ").lower() == 'y':
                run_command("passwd -l root", "Lock root account")

def password_policies():
    """Configure password policies"""
    print_header("PASSWORD POLICIES")
    
    run_command("apt-get install -y libpam-pwquality libpam-cracklib", "Install password quality libraries")
    
    print("\n" + Colors.BOLD + "Configuring PAM password quality..." + Colors.END)
    print("Recommended settings for /etc/pam.d/common-password:")
    print("  password requisite pam_pwquality.so retry=3 minlen=12 difok=4 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3")
    print("  password [success=1 default=ignore] pam_unix.so obscure sha512 remember=12 use_authtok")
    
    if input("\nApply password quality settings? (y/n): ").lower() == 'y':
        run_command("cp /etc/pam.d/common-password /etc/pam.d/common-password.bak", "Backup common-password", ask=False)
        print_warning("Manual editing recommended for /etc/pam.d/common-password")
    
    # Configure password aging
    print("\n" + Colors.BOLD + "Configuring password aging..." + Colors.END)
    if input("Apply password aging settings? (y/n): ").lower() == 'y':
        run_command("cp /etc/login.defs /etc/login.defs.bak", "Backup login.defs", ask=False)
        run_command("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs", "Set max days", ask=False)
        run_command("sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs", "Set min days", ask=False)
        run_command("sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs", "Set warn age", ask=False)
    
    # Account lockout
    print("\n" + Colors.BOLD + "Configure account lockout (faillock)..." + Colors.END)
    print("Add to /etc/pam.d/common-auth:")
    print("  auth required pam_faillock.so preauth silent deny=5 unlock_time=1800")
    print("  auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800")
    
    # Disable null passwords
    if input("\nRemove 'nullok' from PAM config? (y/n): ").lower() == 'y':
        run_command("sed -i 's/nullok//g' /etc/pam.d/common-auth", "Disable null passwords", ask=False)

def disable_guest_and_autologin():
    """Disable guest account and automatic login"""
    print_header("GUEST & AUTOLOGIN")
    
    lightdm_configs = [
        "/etc/lightdm/lightdm.conf",
        "/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
    ]
    
    for config in lightdm_configs:
        if os.path.exists(config):
            print(f"\n{Colors.BOLD}Configuring {config}...{Colors.END}")
            run_command(f"sed -i 's/^autologin-user=.*/#autologin-user=/' {config}", "Disable autologin user", ask=False)
            run_command(f"sed -i 's/^autologin-guest=.*/autologin-guest=false/' {config}", "Disable autologin guest", ask=False)
            
            # Add settings if not present
            run_command(f"grep -q 'allow-guest' {config} || echo 'allow-guest=false' >> {config}", "Disable guest", ask=False)
            run_command(f"grep -q 'greeter-hide-users' {config} || echo 'greeter-hide-users=true' >> {config}", "Hide user list", ask=False)
            run_command(f"grep -q 'greeter-show-manual-login' {config} || echo 'greeter-show-manual-login=true' >> {config}", "Show manual login", ask=False)
            print_success(f"Configured {config}")
    
    # GDM3 configuration
    gdm3_config = "/etc/gdm3/custom.conf"
    if os.path.exists(gdm3_config):
        print(f"\n{Colors.BOLD}Configuring GDM3...{Colors.END}")
        run_command(f"sed -i 's/^AutomaticLoginEnable=.*/AutomaticLoginEnable=false/' {gdm3_config}", "Disable GDM3 autologin", ask=False)

def search_prohibited_files():
    """Search for prohibited files"""
    print_header("PROHIBITED FILES SEARCH")
    
    print(Colors.BOLD + "Common prohibited file types:" + Colors.END)
    print("Media: mp3, mp4, mov, avi, mkv, flv, wav, m4a, wma")
    print("Images: jpg, jpeg, png, gif (sometimes allowed - check README)")
    print("Games: .exe (wine), game ISOs")
    print("Torrents: .torrent")
    
    extensions = input("\nEnter file extensions to search (e.g., mp3 mp4 avi): ").split()
    
    for ext in extensions:
        print(f"\n{Colors.BOLD}Searching for *.{ext} files:{Colors.END}")
        cmd = f"find /home -name '*.{ext}' -type f 2>/dev/null"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
            if input(f"Delete all *.{ext} files? (yes/no): ").lower() == 'yes':
                run_command(f"find /home -name '*.{ext}' -type f -delete", f"Delete *.{ext} files", ask=False)
        else:
            print(f"No *.{ext} files found")
    
    # Search for hacking tools
    print(f"\n{Colors.BOLD}Searching for hacking tools:{Colors.END}")
    tools = ["netcat", "nc", "nmap", "john", "hydra", "ophcrack", "wireshark", "metasploit", 
             "armitage", "aircrack-ng", "burpsuite", "nikto", "sqlmap", "medusa", "truecrack",
             "kismet", "cryptcat", "zenmap"]
    found_tools = []
    for tool in tools:
        result = subprocess.run(f"which {tool}", shell=True, capture_output=True)
        if result.returncode == 0:
            location = result.stdout.decode().strip()
            print_warning(f"Found: {tool} at {location}")
            found_tools.append(tool)
    
    if found_tools and input("\nRemove found hacking tools? (y/n): ").lower() == 'y':
        for tool in found_tools:
            run_command(f"apt-get remove --purge {tool} -y", f"Remove {tool}")

def remove_prohibited_software():
    """Remove commonly prohibited software"""
    print_header("REMOVE PROHIBITED SOFTWARE")
    
    print(Colors.BOLD + "Categories of prohibited software:" + Colors.END)
    
    categories = {
        "Network Services": ["telnet", "rsh-client", "rsh-redone-client"],
        "Remote Access": ["vnc4server", "tightvncserver", "x11vnc"],
        "File Sharing": ["samba", "nfs-kernel-server", "nfs-common"],
        "FTP Servers": ["vsftpd", "ftpd", "pure-ftpd"],
        "Web Servers": ["apache2", "nginx", "lighttpd"],
        "Database Servers": ["mysql-server", "postgresql", "mongodb"],
        "Mail Servers": ["sendmail", "postfix", "dovecot-core"],
        "DNS Servers": ["bind9", "dnsmasq"],
        "P2P/Torrents": ["transmission", "deluge", "vuze", "frostwire"],
        "Games": ["freeciv", "minetest", "minetest-server"],
        "Legacy Services": ["rsh-server", "rlogin", "rexec", "telnetd", "xinetd"]
    }
    
    for category, packages in categories.items():
        print(f"\n{Colors.BOLD}{category}:{Colors.END}")
        for pkg in packages:
            result = subprocess.run(f"dpkg -l | grep -w {pkg}", shell=True, capture_output=True)
            if result.returncode == 0:
                print_warning(f"Found: {pkg}")
                if input(f"Remove {pkg}? (y/n): ").lower() == 'y':
                    run_command(f"apt-get remove --purge {pkg} -y", f"Remove {pkg}", ask=False)
    
    run_command("apt-get autoremove -y", "Clean up dependencies", ask=False)

def secure_ssh():
    """Secure SSH configuration"""
    print_header("SSH SECURITY")
    
    ssh_config = "/etc/ssh/sshd_config"
    if not os.path.exists(ssh_config):
        print_warning("SSH not installed or config not found")
        return
    
    backup = f"{ssh_config}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    run_command(f"cp {ssh_config} {backup}", "Backup SSH config", ask=False)
    
    print("\nRecommended SSH hardening:")
    settings = {
        "Protocol": "2",
        "LogLevel": "VERBOSE",
        "X11Forwarding": "no",
        "MaxAuthTries": "4",
        "IgnoreRhosts": "yes",
        "HostbasedAuthentication": "no",
        "PermitRootLogin": "no",
        "PermitEmptyPasswords": "no",
        "PasswordAuthentication": "yes"
    }
    
    for key, value in settings.items():
        print(f"  {key} {value}")
    
    if input("\nApply recommended SSH settings? (y/n): ").lower() == 'y':
        for key, value in settings.items():
            run_command(f"sed -i 's/^#*{key}.*/{key} {value}/' {ssh_config}", f"Set {key}", ask=False)
        run_command("systemctl restart sshd", "Restart SSH service")

def configure_sudoers():
    """Configure sudo to require authentication"""
    print_header("SUDOERS CONFIGURATION")
    
    print(Colors.BOLD + "Checking sudoers configuration..." + Colors.END)
    
    # Check main sudoers file
    result = subprocess.run("grep -E 'NOPASSWD|!authenticate' /etc/sudoers", shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print_warning("Found NOPASSWD or !authenticate in /etc/sudoers:")
        print(result.stdout)
        print("\nThese should be removed to require password for sudo")
    
    # Check sudoers.d directory
    print("\n" + Colors.BOLD + "Checking /etc/sudoers.d for unauthorized entries..." + Colors.END)
    run_command("ls -la /etc/sudoers.d", "List sudoers.d files", ask=False)
    run_command("grep -r 'NOPASSWD' /etc/sudoers.d/ 2>/dev/null", "Search for NOPASSWD", ask=False)
    
    # Ensure authentication is required
    result = subprocess.run("grep 'Defaults authenticate' /etc/sudoers", shell=True, capture_output=True)
    if result.returncode != 0:
        print_warning("'Defaults authenticate' not found in /etc/sudoers")
        if input("Add authentication requirement? (y/n): ").lower() == 'y':
            run_command("echo 'Defaults authenticate' >> /etc/sudoers", "Add authentication requirement")

def check_services():
    """List and manage services"""
    print_header("SERVICE MANAGEMENT")
    
    print(Colors.BOLD + "Currently active services:" + Colors.END)
    run_command("systemctl list-units --type=service --state=active --no-pager", "List active services", ask=False)
    
    print("\n" + Colors.BOLD + "Commonly suspicious services:" + Colors.END)
    suspicious = ["nginx", "apache2", "telnet", "ftp", "vsftpd", "samba", "nfs", "bind9", 
                  "xinetd", "tightvncserver", "x11vnc"]
    for service in suspicious:
        result = subprocess.run(f"systemctl is-active {service}", shell=True, capture_output=True, text=True)
        if result.stdout.strip() == "active":
            print_warning(f"{service} is running")
    
    while True:
        service = input("\nEnter service to disable (or press Enter to skip): ")
        if not service:
            break
        run_command(f"systemctl stop {service}", f"Stop {service}")
        run_command(f"systemctl disable {service}", f"Disable {service}")

def kernel_hardening():
    """Configure kernel security parameters"""
    print_header("KERNEL HARDENING")
    
    sysctl_conf = "/etc/sysctl.conf"
    run_command(f"cp {sysctl_conf} {sysctl_conf}.bak", "Backup sysctl.conf", ask=False)
    
    print(Colors.BOLD + "Security parameters to configure:" + Colors.END)
    
    params = {
        "net.ipv4.ip_forward": "0",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.default.accept_source_route": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.default.accept_redirects": "0",
        "net.ipv4.conf.all.secure_redirects": "0",
        "net.ipv4.conf.default.secure_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.default.send_redirects": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1"
    }
    
    for key, value in params.items():
        print(f"  {key} = {value}")
    
    if input("\nApply kernel hardening? (y/n): ").lower() == 'y':
        for key, value in params.items():
            cmd = f"grep -q '^{key}' {sysctl_conf} && sed -i 's/^{key}.*/{key} = {value}/' {sysctl_conf} || echo '{key} = {value}' >> {sysctl_conf}"
            subprocess.run(cmd, shell=True)
        run_command("sysctl -p", "Apply sysctl changes", ask=False)
    
    # Disable IPv6 if not needed
    if input("\nDisable IPv6? (y/n): ").lower() == 'y':
        run_command("echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf", "Disable IPv6", ask=False)
        run_command("echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.conf", "Disable IPv6 default", ask=False)
        run_command("sysctl -p", "Apply changes", ask=False)

def check_file_permissions():
    """Check and fix critical file permissions"""
    print_header("FILE PERMISSIONS")
    
    print(Colors.BOLD + "Checking critical file permissions..." + Colors.END)
    
    critical_files = {
        "/etc/shadow": "640",
        "/etc/passwd": "644",
        "/etc/group": "644",
        "/etc/gshadow": "640",
        "/etc/ssh/sshd_config": "600",
        "/boot/grub/grub.cfg": "600"
    }
    
    for filepath, perm in critical_files.items():
        if os.path.exists(filepath):
            run_command(f"ls -l {filepath}", f"Check {filepath}", ask=False)
            if input(f"Set {filepath} to {perm}? (y/n): ").lower() == 'y':
                run_command(f"chmod {perm} {filepath}", f"Set permissions")

def check_startup_scripts():
    """Check for malicious startup scripts"""
    print_header("STARTUP SCRIPTS CHECK")
    
    print(Colors.BOLD + "Checking startup locations..." + Colors.END)
    
    locations = [
        "/etc/rc.local",
        "/etc/init.d/",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
        "/var/spool/cron/crontabs/",
        "~/.bashrc",
        "~/.bash_profile",
        "/etc/profile"
    ]
    
    for loc in locations:
        if os.path.exists(loc.replace("~", os.path.expanduser("~"))):
            print(f"\n{Colors.BOLD}Checking {loc}:{Colors.END}")
            run_command(f"ls -la {loc}", f"List {loc}", ask=False)
    
    # Check crontab
    print("\n" + Colors.BOLD + "Current user crontabs:" + Colors.END)
    run_command("crontab -l", "Show current crontab", ask=False)
    
    # Check for suspicious cron jobs
    print("\n" + Colors.BOLD + "Checking /etc/crontab:" + Colors.END)
    run_command("cat /etc/crontab", "Display crontab", ask=False)
    
    if input("\nClear all user cron jobs? (y/n): ").lower() == 'y':
        run_command("crontab -r", "Remove cron jobs")

# -------------------------------
# (Paste this to replace/complete the truncated part)
# -------------------------------

def check_backdoors():
    """Check for backdoors and suspicious connections"""
    print_header("BACKDOOR DETECTION")
    
    print(Colors.BOLD + "1. Checking for listening ports..." + Colors.END)
    run_command("ss -tlnp", "Show listening TCP ports", ask=False)
    run_command("netstat -tulpn 2>/dev/null || ss -tulpn", "Alternative port check", ask=False)
    
    print("\n" + Colors.BOLD + "2. Checking established connections..." + Colors.END)
    run_command("ss -tunp", "Show active connections", ask=False)
    
    print("\n" + Colors.BOLD + "3. Checking /etc/hosts for suspicious entries..." + Colors.END)
    run_command("cat /etc/hosts", "Display hosts file", ask=False)
    
    if input("\nReset /etc/hosts to defaults? (y/n): ").lower() == 'y':
        # Backup first
        backup_hosts = f"/etc/hosts.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        run_command(f"cp /etc/hosts {backup_hosts}", f"Backup /etc/hosts to {backup_hosts}", ask=False)
        default_hosts = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n# The following lines are desirable for IPv4/IPv6 capable hosts\n127.0.1.1\t" + os.uname().nodename + "\n"
        try:
            with open("/etc/hosts", "w") as hf:
                hf.write(default_hosts)
            print_success("Rewrote /etc/hosts to safe defaults")
        except Exception as e:
            print_error(f"Failed to write /etc/hosts: {e}")
    
    # Quick look for suspicious binaries in /tmp or /dev/shm
    print("\n" + Colors.BOLD + "4. Searching for suspicious executables in /tmp and /dev/shm..." + Colors.END)
    run_command("find /tmp /dev/shm -type f -perm -o+x -ls 2>/dev/null | head -50", "Find exec files in /tmp & /dev/shm", ask=False)
    
    # Check for unusual SUID/SGID binaries
    print("\n" + Colors.BOLD + "5. Checking SUID/SGID binaries (top 50):" + Colors.END)
    run_command("find / -perm /6000 -type f -ls 2>/dev/null | head -50", "List SUID/SGID binaries", ask=False)

def integrity_checks():
    """Perform integrity and suspicious-file checks"""
    print_header("INTEGRITY CHECKS")
    
    # Check for dpkg/apt issues
    print("\n" + Colors.BOLD + "1. Check for broken packages or missing signatures:" + Colors.END)
    run_command("apt-get check", "apt-get check", ask=False)
    run_command("dpkg --audit", "dpkg audit", ask=False)
    
    # Check for recently modified critical files (last 7 days)
    print("\n" + Colors.BOLD + "2. Recently modified critical files (7 days):" + Colors.END)
    run_command("find /etc -type f -mtime -7 -ls | head -100", "Recently modified /etc files", ask=False)
    
    # Quick rootkit scan (if chkrootkit installed)
    print("\n" + Colors.BOLD + "3. Rootkit checks (chkrootkit/rkhunter if available):" + Colors.END)
    run_command("which chkrootkit || true", "Check chkrootkit presence", ask=False)
    if input("Run chkrootkit if installed? (y/n): ").lower() == 'y':
        run_command("chkrootkit || true", "Run chkrootkit (may be slow)", ask=False)
    if input("Run rkhunter if installed? (y/n): ").lower() == 'y':
        run_command("rkhunter --check --sk --nocolors || true", "Run rkhunter (may be slow)", ask=False)
    
    # Check auth log for repeated failures (last 200 lines)
    print("\n" + Colors.BOLD + "4. Authentication failures (last 200 lines of auth.log):" + Colors.END)
    run_command("tail -n 200 /var/log/auth.log 2>/dev/null | egrep -i 'fail|failed|invalid' || true", "Show auth failures", ask=False)

def collect_artifacts():
    """Collect useful artifacts into a timestamped tarball for offline review"""
    print_header("COLLECT ARTIFACTS")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = f"/tmp/cp_artifacts_{ts}"
    os.makedirs(outdir, exist_ok=True)
    print(f"Collecting artifacts into {outdir} (you will be prompted before each copy)...")
    
    items = [
        "/etc/hosts",
        "/etc/ssh/sshd_config",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/dpkg.log",
        "/etc/apt/sources.list",
        "/etc/apt/sources.list.d"
    ]
    for item in items:
        if os.path.exists(item):
            dest = os.path.join(outdir, os.path.basename(item))
            run_command(f"cp -a {item} {dest}", f"Copy {item} -> {dest}", ask=False)
    
    tarball = f"/tmp/cp_artifacts_{ts}.tar.gz"
    run_command(f"tar -czf {tarball} -C /tmp cp_artifacts_{ts}", f"Create tarball {tarball}", ask=False)
    print_success(f"Artifacts collected into {tarball}")
    print("You can now download this tarball from the VM for offline analysis.")

def main_menu():
    """Main interactive menu - ties together all helpers"""
    while True:
        print_header("CYBERPATRIOT LINUX SECURITY - ADVANCED")
        print("0.  System Information")
        print("1.  System Updates")
        print("2.  Configure Automatic Updates")
        print("3.  Install Security Tools (ClamAV, auditd, fail2ban, AppArmor)")
        print("4.  Configure Firewall (UFW)")
        print("5.  User Management")
        print("6.  Password Policies")
        print("7.  Guest/Autologin Disable")
        print("8.  Search for Prohibited Files")
        print("9.  Remove Prohibited Software")
        print("10. Secure SSH")
        print("11. Configure Sudoers")
        print("12. Check & Manage Services")
        print("13. Kernel Hardening")
        print("14. File Permissions Check")
        print("15. Startup Scripts Check")
        print("16. Backdoor Detection")
        print("17. Integrity Checks (rootkits, logs)")
        print("18. Collect Artifacts (for offline analysis)")
        print("99. Exit")
        
        choice = input("\nSelect option: ").strip()
        if choice == '0':
            system_info()
        elif choice == '1':
            system_updates()
        elif choice == '2':
            configure_automatic_updates()
        elif choice == '3':
            install_security_tools()
        elif choice == '4':
            configure_firewall()
        elif choice == '5':
            manage_users()
        elif choice == '6':
            password_policies()
        elif choice == '7':
            disable_guest_and_autologin()
        elif choice == '8':
            search_prohibited_files()
        elif choice == '9':
            remove_prohibited_software()
        elif choice == '10':
            secure_ssh()
        elif choice == '11':
            configure_sudoers()
        elif choice == '12':
            check_services()
        elif choice == '13':
            kernel_hardening()
        elif choice == '14':
            check_file_permissions()
        elif choice == '15':
            check_startup_scripts()
        elif choice == '16':
            check_backdoors()
        elif choice == '17':
            integrity_checks()
        elif choice == '18':
            collect_artifacts()
        elif choice == '99':
            print("\n" + Colors.GREEN + "Exiting. Good luck in the competition!" + Colors.END)
            break
        else:
            print_error("Invalid option!")
        input("\nPress Enter to continue...")

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
