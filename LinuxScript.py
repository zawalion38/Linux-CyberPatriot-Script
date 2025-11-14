#!/usr/bin/env python3
"""
CyberPatriot Linux Security Automation Script
Helps systematically complete Linux security tasks for CyberPatriot competitions
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

def system_updates():
    """Handle system updates"""
    print_header("SYSTEM UPDATES")
    run_command("apt-get update", "Update package lists")
    run_command("apt-get upgrade -y", "Upgrade installed packages")
    run_command("apt-get dist-upgrade -y", "Perform distribution upgrade")
    run_command("apt-get autoremove -y", "Remove unnecessary packages")

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

def install_antivirus():
    """Install and configure ClamAV antivirus"""
    print_header("ANTIVIRUS (ClamAV)")
    run_command("apt-get install clamav clamav-daemon clamtk -y", "Install ClamAV")
    run_command("systemctl stop clamav-freshclam", "Stop freshclam service temporarily")
    run_command("freshclam", "Update virus definitions")
    run_command("systemctl start clamav-freshclam", "Start freshclam service")
    
    print_warning("\nFull system scan commands (run in background):")
    print("  sudo clamscan -r -i --remove=yes / &")
    print("  sudo clamscan -r --remove /home &")

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
    
    run_command("ufw enable", "Enable firewall")
    run_command("ufw status verbose", "Show firewall status", ask=False)

def manage_users():
    """User and password management"""
    print_header("USER MANAGEMENT")
    
    # List current users
    print(Colors.BOLD + "Current users with login shells:" + Colors.END)
    run_command("cut -d: -f1 /etc/passwd", "List all users", ask=False)
    
    print("\n" + Colors.BOLD + "Admin users (sudo group):" + Colors.END)
    run_command("getent group sudo", "Show sudo group members", ask=False)
    
    print("\n" + Colors.BOLD + "User Management Tasks:" + Colors.END)
    print("1. Change user passwords")
    print("2. Change ALL user passwords (bulk)")
    print("3. Delete unauthorized users")
    print("4. Add missing users")
    print("5. Manage sudo privileges")
    print("6. Lock/disable accounts")
    print("7. Check for UID 0 users (root equivalents)")
    
    while True:
        choice = input("\nSelect task (1-7) or 'q' to quit: ")
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

def password_policies():
    """Configure password policies"""
    print_header("PASSWORD POLICIES")
    
    run_command("apt-get install -y libpam-pwquality libpam-cracklib", "Install password quality libraries")
    
    print("\n" + Colors.BOLD + "Configuring PAM password quality..." + Colors.END)
    print("Edit /etc/pam.d/common-password with these settings:")
    print("  password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1")
    print("  password [success=1 default=ignore] pam_unix.so remember=5")
    
    if input("\nApply password quality settings? (y/n): ").lower() == 'y':
        # Backup first
        run_command("cp /etc/pam.d/common-password /etc/pam.d/common-password.bak", "Backup common-password", ask=False)
        
        # Note: Actual sed commands would go here - manual verification recommended
        print_warning("Manual verification recommended. Edit /etc/pam.d/common-password")
    
    # Configure password aging in login.defs
    print("\n" + Colors.BOLD + "Configuring password aging in /etc/login.defs..." + Colors.END)
    print("  PASS_MAX_DAYS 90")
    print("  PASS_MIN_DAYS 10")
    print("  PASS_WARN_AGE 7")
    
    if input("\nApply password aging settings? (y/n): ").lower() == 'y':
        run_command("cp /etc/login.defs /etc/login.defs.bak", "Backup login.defs", ask=False)
        run_command("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs", "Set max days", ask=False)
        run_command("sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs", "Set min days", ask=False)
        run_command("sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs", "Set warn age", ask=False)
    
    # Account lockout policy
    print("\n" + Colors.BOLD + "Configure account lockout (faillock)..." + Colors.END)
    print("Add to /etc/pam.d/common-auth:")
    print("  auth required pam_faillock.so preauth silent deny=5 unlock_time=1800")
    print("  auth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800")
    
    # Disable null passwords
    print("\n" + Colors.BOLD + "Disable null passwords..." + Colors.END)
    if input("Remove 'nullok' from PAM config? (y/n): ").lower() == 'y':
        run_command("sed -i 's/nullok//g' /etc/pam.d/common-auth", "Disable null passwords", ask=False)

def disable_autologin():
    """Disable automatic login"""
    print_header("DISABLE AUTOLOGIN")
    
    lightdm_config = "/etc/lightdm/lightdm.conf"
    if os.path.exists(lightdm_config):
        print(Colors.BOLD + "Disabling autologin in lightdm.conf..." + Colors.END)
        run_command(f"sed -i 's/^autologin-user=/#autologin-user=/' {lightdm_config}", "Disable autologin user", ask=False)
        run_command(f"sed -i 's/^autologin-guest=.*/autologin-guest=false/' {lightdm_config}", "Disable autologin guest", ask=False)
        print_success("Autologin disabled")
    else:
        print_warning("lightdm.conf not found - may be using different display manager")

def search_prohibited_files():
    """Search for prohibited files"""
    print_header("PROHIBITED FILES SEARCH")
    
    print(Colors.BOLD + "Common prohibited file types:" + Colors.END)
    print("Media: mp3, mp4, mov, avi, mkv, flv, wav, m4a")
    print("Images: jpg, jpeg, png, gif (sometimes allowed)")
    print("Games: .exe (wine), game-related")
    
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
    tools = ["netcat", "nc", "nmap", "john", "hydra", "ophcrack", "wireshark", "metasploit", "armitage", "aircrack-ng", "burpsuite"]
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
    
    print(Colors.BOLD + "Checking for prohibited services/software..." + Colors.END)
    
    prohibited = ["telnet", "ftp", "vsftpd", "rsh", "rlogin", "nfs", "nis", "samba", "apache2", "bind9", "nginx", "vnc"]
    
    run_command("dpkg --list | egrep 'telnet|ftp|vsftpd|rsh|rlogin|nfs|nis|samba|apache|bind9|nginx|vnc'", 
                "List prohibited packages", ask=False)
    
    print("\n" + Colors.BOLD + "Remove packages individually:" + Colors.END)
    for pkg in prohibited:
        result = subprocess.run(f"dpkg -l | grep -w {pkg}", shell=True, capture_output=True)
        if result.returncode == 0:
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
    print("  PermitRootLogin no")
    print("  PasswordAuthentication yes")
    print("  PermitEmptyPasswords no")
    print("  Protocol 2")
    print("  X11Forwarding no")
    
    if input("\nApply recommended SSH settings? (y/n): ").lower() == 'y':
        run_command("sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config", "Disable root login", ask=False)
        run_command("sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config", "Enable password auth", ask=False)
        run_command("sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config", "Disable empty passwords", ask=False)
        run_command("sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config", "Disable X11 forwarding", ask=False)
        run_command("systemctl restart sshd", "Restart SSH service")

def configure_sudoers():
    """Configure sudo to require authentication"""
    print_header("SUDOERS CONFIGURATION")
    
    print(Colors.BOLD + "Ensuring sudo requires authentication..." + Colors.END)
    
    # Check if authentication is required
    result = subprocess.run("grep 'Defaults authenticate' /etc/sudoers", shell=True, capture_output=True)
    if result.returncode != 0:
        print_warning("'Defaults authenticate' not found in /etc/sudoers")
        if input("Add authentication requirement? (y/n): ").lower() == 'y':
            run_command("echo 'Defaults authenticate' >> /etc/sudoers", "Add authentication requirement")
    else:
        print_success("Sudo authentication already configured")

def check_services():
    """List and manage services"""
    print_header("SERVICE MANAGEMENT")
    
    print(Colors.BOLD + "Currently active services:" + Colors.END)
    run_command("systemctl list-units --type=service --state=active", "List active services", ask=False)
    
    print("\n" + Colors.YELLOW + "Review services and disable unnecessary ones" + Colors.END)
    print("Common suspicious services: nginx, apache2, telnet, ftp, vsftpd")
    
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
    print("  net.ipv4.ip_forward=0 (disable IP forwarding)")
    print("  net.ipv4.tcp_syncookies=1 (enable SYN cookie protection)")
    
    if input("\nApply kernel hardening? (y/n): ").lower() == 'y':
        run_command("sed -i 's/^#*net.ipv4.ip_forward.*/net.ipv4.ip_forward=0/' /etc/sysctl.conf", "Disable IP forwarding", ask=False)
        run_command("sed -i 's/^#*net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf", "Enable SYN cookies", ask=False)
        run_command("sysctl -p", "Apply sysctl changes", ask=False)

def check_file_permissions():
    """Check and fix critical file permissions"""
    print_header("FILE PERMISSIONS")
    
    print(Colors.BOLD + "Checking critical file permissions..." + Colors.END)
    
    # Check /etc/shadow
    run_command("ls -l /etc/shadow", "Check /etc/shadow permissions", ask=False)
    if input("Set /etc/shadow to 640? (y/n): ").lower() == 'y':
        run_command("chmod 640 /etc/shadow", "Set shadow permissions")
    
    # Check /etc/passwd
    run_command("ls -l /etc/passwd", "Check /etc/passwd permissions", ask=False)
    if input("Set /etc/passwd to 644? (y/n): ").lower() == 'y':
        run_command("chmod 644 /etc/passwd", "Set passwd permissions")

def check_backdoors():
    """Check for backdoors and suspicious connections"""
    print_header("BACKDOOR DETECTION")
    
    print(Colors.BOLD + "Checking for listening ports and connections..." + Colors.END)
    run_command("ss -tlnp", "Show listening TCP ports", ask=False)
    
    print("\n" + Colors.BOLD + "Checking cron jobs for backdoors..." + Colors.END)
    run_command("cat /etc/crontab", "Show crontab", ask=False)
    
    print_warning("Look for suspicious entries like netcat (nc), reverse shells, or unusual scripts")
    
    if input("\nKill all netcat processes? (y/n): ").lower() == 'y':
        run_command("pkill -f nc.traditional", "Kill netcat traditional", ask=False)
        run_command("pkill -f nc", "Kill netcat", ask=False)
        run_command("which nc.traditional", "Find netcat location", ask=False)
        if input("Remove netcat binary? (y/n): ").lower() == 'y':
            run_command("rm /usr/bin/nc.traditional", "Remove netcat", ask=False)

def configure_firefox():
    """Display Firefox security settings"""
    print_header("FIREFOX SECURITY")
    
    print(Colors.BOLD + "Manual Firefox configuration (Privacy & Security):" + Colors.END)
    print("✓ Don't ask to save logins")
    print("✓ Show alerts about passwords for breached websites")
    print("✓ Firefox can remember history (OK)")
    print("✓ Block pop-up windows")
    print("✓ Warn you about add-ons")
    print("✓ Block dangerous and deceptive content")
    print("✓ Block dangerous downloads")
    print("✓ Consider deleting cookies")
    print("\nPress Enter to continue...")
    input()

def security_audit():
    """Run comprehensive security audit"""
    print_header("SECURITY AUDIT")
    
    print(Colors.BOLD + "1. Users with UID 0 (should only be root):" + Colors.END)
    run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd", "Check UID 0 users", ask=False)
    
    print("\n" + Colors.BOLD + "2. Users with empty passwords:" + Colors.END)
    run_command("awk -F: '$2 == \"\" {print $1}' /etc/shadow 2>/dev/null", "Check empty passwords", ask=False)
    
    print("\n" + Colors.BOLD + "3. Checking for world-writable files:" + Colors.END)
    print_warning("This may take several minutes...")
    run_command("find / -xdev -type f -perm -0002 -ls 2>/dev/null | head -20", "Find world-writable files", ask=False)
    
    print("\n" + Colors.BOLD + "4. Checking SUID/SGID files:" + Colors.END)
    run_command("find / -perm -4000 -type f 2>/dev/null | head -20", "Find SUID files", ask=False)
    
    print("\n" + Colors.BOLD + "5. Checking all user groups:" + Colors.END)
    run_command("cat /etc/group", "List all groups", ask=False)

def main_menu():
    """Display and handle main menu"""
    while True:
        print_header("CYBERPATRIOT LINUX SECURITY SCRIPT")
        print("0.  System Information")
        print("1.  System Updates")
        print("2.  Configure Automatic Updates")
        print("3.  Install & Configure Antivirus (ClamAV)")
        print("4.  Configure Firewall (UFW)")
        print("5.  User Management")
        print("6.  Password Policies")
        print("7.  Disable Autologin")
        print("8.  Search for Prohibited Files")
        print("9.  Remove Prohibited Software")
        print("10. Secure SSH")
        print("11. Configure Sudoers")
        print("12. Check & Manage Services")
        print("13. Kernel Hardening (IPv4/SYN Cookies)")
        print("14. Check File Permissions")
        print("15. Check for Backdoors")
        print("16. Firefox Security Settings")
        print("17. Security Audit")
        print("18. Run Critical Tasks (Auto Mode)")
        print("99. Exit")
        
        choice = input("\nSelect option: ")
        
        if choice == '0':
            system_info()
        elif choice == '1':
            system_updates()
        elif choice == '2':
            configure_automatic_updates()
        elif choice == '3':
            install_antivirus()
        elif choice == '4':
            configure_firewall()
        elif choice == '5':
            manage_users()
        elif choice == '6':
            password_policies()
        elif choice == '7':
            disable_autologin()
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
            check_backdoors()
        elif choice == '16':
            configure_firefox()
        elif choice == '17':
            security_audit()
        elif choice == '18':
            print_warning("Running critical tasks in sequence...")
            system_info()
            system_updates()
            configure_automatic_updates()
            install_antivirus()
            configure_firewall()
            password_policies()
            disable_autologin()
            remove_prohibited_software()
            secure_ssh()
            configure_sudoers()
            kernel_hardening()
            check_file_permissions()
            security_audit()
            print_success("All automated tasks completed!")
        elif choice == '99':
            print("\n" + Colors.GREEN + "Good luck with the competition!" + Colors.END)
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