#!/bin/bash

################################################################################
# Enhanced Linux Security Hardening Script
# Version: 2.0
# Compatible with: Ubuntu 18.04+ and Debian 12.0+
################################################################################

# Global variables
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/hardening.log"
SCRIPT_NAME=$(basename "$0")
VERBOSE=false

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

################################################################################
# Core Functions
################################################################################

# Function for logging
log() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): $1"
    echo "$message" | sudo tee -a "$LOG_FILE" >/dev/null
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): WARNING: $1"
    echo "$message" | sudo tee -a "$LOG_FILE" >/dev/null
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): ERROR: $1"
    echo "$message" | sudo tee -a "$LOG_FILE" >/dev/null
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function for error handling
handle_error() {
    log_error "$1"
    read -p "Do you want to continue despite this error? (y/N): " continue_on_error
    case $continue_on_error in
        [Yy]* ) 
            log_warning "Continuing despite error..."
            return 0
            ;;
        * ) 
            log_error "Exiting due to error"
            exit 1
            ;;
    esac
}

# Function to install packages
install_package() {
    if dpkg -l | grep -qw "$1"; then
        log "Package $1 is already installed"
        return 0
    fi
    
    log "Installing $1..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        log "Successfully installed $1"
        return 0
    else
        handle_error "Failed to install $1"
        return 1
    fi
}

# Function to backup files
backup_files() {
    log "Creating backup directory..."
    sudo mkdir -p "$BACKUP_DIR" || handle_error "Failed to create backup directory"
    
    local files_to_backup=(
        "/etc/default/grub"
        "/etc/ssh/sshd_config"
        "/etc/pam.d/common-password"
        "/etc/login.defs"
        "/etc/sysctl.conf"
        "/etc/security/limits.conf"
        "/etc/fstab"
    )
    
    for file in "${files_to_backup[@]}"; do
        if [ -f "$file" ]; then
            sudo cp -a "$file" "$BACKUP_DIR/" && log "Backed up $file" || log_warning "Failed to backup $file"
        else
            log_warning "$file not found, skipping backup"
        fi
    done
    
    log "Backup created in $BACKUP_DIR"
}

# Function to restore from backup
restore_backup() {
    local latest_backup=$(ls -td /root/security_backup_* 2>/dev/null | head -1)
    
    if [ -z "$latest_backup" ]; then
        log_error "No backup directory found. Cannot restore."
        exit 1
    fi
    
    log "Restoring from: $latest_backup"
    
    for file in "$latest_backup"/*; do
        if [ -f "$file" ]; then
            local filename=$(basename "$file")
            local dest=""
            
            # Determine destination based on filename
            case $filename in
                grub) dest="/etc/default/grub" ;;
                sshd_config) dest="/etc/ssh/sshd_config" ;;
                common-password) dest="/etc/pam.d/common-password" ;;
                login.defs) dest="/etc/login.defs" ;;
                sysctl.conf) dest="/etc/sysctl.conf" ;;
                limits.conf) dest="/etc/security/limits.conf" ;;
                fstab) dest="/etc/fstab" ;;
                *) 
                    log_warning "Unknown backup file: $filename"
                    continue
                    ;;
            esac
            
            sudo cp "$file" "$dest" && log "Restored $dest" || log_warning "Failed to restore $dest"
        fi
    done
    
    log "Restoration complete from $latest_backup"
}

# Function to check permissions
check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}This script must be run with sudo privileges.${NC}"
        echo "Please run it again using: sudo $0"
        exit 1
    fi
}

# Function to display help
display_help() {
    cat << EOF
Usage: sudo ./$SCRIPT_NAME [OPTIONS]

Enhanced Linux Security Hardening Script

Options:
  -h, --help         Display this help message
  -v, --verbose      Enable verbose output
  --restore          Restore system from the most recent backup
  --skip-update      Skip system update step
  --minimal          Run minimal hardening (skip optional components)

Examples:
  sudo ./$SCRIPT_NAME              # Run full hardening
  sudo ./$SCRIPT_NAME --restore    # Restore from backup
  sudo ./$SCRIPT_NAME --minimal    # Run minimal hardening

EOF
    exit 0
}

# Function to check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    if ! command -v lsb_release &> /dev/null; then
        handle_error "lsb_release command not found. This script requires an Ubuntu or Debian-based system."
        return 1
    fi

    local os_name=$(lsb_release -si)
    local os_version=$(lsb_release -sr)

    if [[ "$os_name" != "Ubuntu" && "$os_name" != "Debian" ]]; then
        handle_error "This script is designed for Ubuntu or Debian-based systems. Detected OS: $os_name"
        return 1
    fi

    # Check Ubuntu version
    if [[ "$os_name" == "Ubuntu" ]]; then
        local major_version=$(echo "$os_version" | cut -d'.' -f1)
        if [[ $major_version -lt 18 ]]; then
            handle_error "This script requires Ubuntu 18.04 or later. Detected version: $os_version"
            return 1
        fi
    fi
    
    # Check Debian version
    if [[ "$os_name" == "Debian" ]]; then
        local major_version=$(echo "$os_version" | cut -d'.' -f1)
        if [[ $major_version -lt 10 ]]; then
            handle_error "This script requires Debian 10.0 or later. Detected version: $os_version"
            return 1
        fi
    fi

    log "System requirements check passed. OS: $os_name $os_version"
}

# Function to update system
update_system() {
    log "Updating system packages..."
    sudo apt-get update -y 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || handle_error "System update failed"
    sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || handle_error "System upgrade failed"
    log "System update completed"
}

################################################################################
# User Management
################################################################################

user_management() {
    log "Starting user management..."
    
    # Get the actual user who invoked sudo
    local actual_user="${SUDO_USER:-$(logname 2>/dev/null)}"
    if [ -z "$actual_user" ]; then
        log_error "Cannot determine the actual user. Skipping user management."
        return 1
    fi
    
    log "Detected user: $actual_user"
    
    # Password management
    echo ""
    echo "=== Password Configuration ==="
    read -sp "Enter password for $actual_user: " ADMIN_PASS
    echo ""
    read -sp "Enter password for root account: " ROOT_PASS
    echo ""
    read -sp "Enter password for new sudo service account: " SUDO_PASS
    echo ""
    echo ""

    # Change passwords
    echo "$actual_user:$ADMIN_PASS" | sudo chpasswd || log_warning "Failed to change password for $actual_user"
    echo "root:$ROOT_PASS" | sudo chpasswd || log_warning "Failed to change root password"

    # Create a sudoers account that cannot log in (for service accounts)
    SUDO_USER="sudo_service"
    if ! id "$SUDO_USER" &>/dev/null; then
        sudo useradd -M -s /usr/sbin/nologin "$SUDO_USER" || log_warning "Failed to create $SUDO_USER"
        echo "$SUDO_USER:$SUDO_PASS" | sudo chpasswd || log_warning "Failed to set password for $SUDO_USER"
        sudo usermod -aG sudo "$SUDO_USER" || log_warning "Failed to add $SUDO_USER to sudo group"
        log "Created $SUDO_USER with sudo privileges but no login access"
    else
        log "$SUDO_USER already exists, skipping creation"
    fi

    BASE_USERS=("root" "$actual_user" "$SUDO_USER")

    # User cleanup
    read -p "Do you want to remove non-default users? (y/N): " remove_users
    if [[ "$remove_users" =~ ^[Yy]$ ]]; then
        log "Removing non-default users..."
        for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
            if [[ ! " ${BASE_USERS[@]} " =~ " ${user} " ]]; then
                sudo userdel -r "$user" 2>/dev/null && log "Removed user: $user" || log_warning "Failed to remove user: $user"
            fi
        done
    fi

    # Add users from config file
    USER_FILE="/root/userlist.txt"
    if [[ -f "$USER_FILE" ]]; then
        log "Adding users from $USER_FILE..."
        while IFS="::" read -r username groups locked; do
            # Skip empty lines and comments
            [[ -z "$username" || "$username" =~ ^# ]] && continue
            
            if id "$username" &>/dev/null; then
                log "User $username already exists, skipping..."
            else
                sudo useradd -m -s /bin/bash -G "$groups" "$username" || log_warning "Failed to create user: $username"
                if [[ "$locked" == "yes" ]]; then
                    sudo passwd -l "$username" && log "Created locked user: $username with groups: $groups"
                else
                    log "Created user: $username with groups: $groups"
                fi
            fi
        done < "$USER_FILE"
    else
        log_warning "User config file not found: $USER_FILE"
    fi

    # Restricted shell assignment
    read -p "Do you want to restrict users with rbash? (y/N): " restrict_users
    if [[ "$restrict_users" =~ ^[Yy]$ ]]; then
        read -p "Enter space-separated list of users to exempt from restriction: " EXEMPT_USERS
        IFS=' ' read -ra EXEMPT_ARRAY <<< "$EXEMPT_USERS"
        
        log "Applying restricted shells..."
        for user in $(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /nologin|false/ {print $1}' /etc/passwd); do
            if [[ ! " ${EXEMPT_ARRAY[@]} " =~ " $user " ]]; then
                sudo chsh -s /bin/rbash "$user" && log "Set restricted shell for $user" || log_warning "Failed to set rbash for $user"
            else
                log "Exempted user from restriction: $user"
            fi
        done
    fi

    log "User management completed"
}

################################################################################
# Firewall Configuration
################################################################################

setup_firewall() {
    log "Installing and configuring UFW firewall..."
    install_package "ufw" || return 1
    
    # Reset UFW to default state
    sudo ufw --force reset 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null
    
    # Set default policies
    sudo ufw default deny incoming || handle_error "Failed to set UFW default incoming policy"
    sudo ufw default allow outgoing || handle_error "Failed to set UFW default outgoing policy"
    
    # Allow essential services
    sudo ufw limit ssh comment 'SSH with rate limiting' || handle_error "Failed to configure SSH in UFW"
    
    # Ask about web services
    read -p "Do you want to allow HTTP/HTTPS traffic? (Y/n): " allow_web
    if [[ ! "$allow_web" =~ ^[Nn]$ ]]; then
        sudo ufw allow 80/tcp comment 'HTTP' || log_warning "Failed to allow HTTP"
        sudo ufw allow 443/tcp comment 'HTTPS' || log_warning "Failed to allow HTTPS"
    fi
    
    # IPv6 configuration
    read -p "Do you want to apply IPv6-specific firewall rules? (y/N): " apply_ipv6_rules
    if [[ "$apply_ipv6_rules" =~ ^[Yy]$ ]]; then
        log "Applying IPv6-specific firewall rules..."
        sudo ufw allow in on lo || log_warning "Failed to allow loopback traffic"
        sudo ufw allow out on lo || log_warning "Failed to allow loopback traffic"
    fi
    
    # Enable logging
    sudo ufw logging on || log_warning "Failed to enable UFW logging"
    
    # Enable firewall
    sudo ufw --force enable || handle_error "Failed to enable UFW"
    
    log "Firewall configured and enabled"
    sudo ufw status verbose | sudo tee -a "$LOG_FILE"
}

################################################################################
# Intrusion Detection/Prevention
################################################################################

setup_suricata() {
    log "Installing and configuring Suricata IDS/IPS..."
    install_package "suricata" || return 1
    
    # Update Suricata rules
    sudo suricata-update update-sources 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to update Suricata sources"
    sudo suricata-update 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to update Suricata rules"
    
    # Enable and start service
    sudo systemctl enable suricata || log_warning "Failed to enable Suricata service"
    sudo systemctl restart suricata || log_warning "Failed to restart Suricata service"
    
    log "Suricata configured and started"
}

setup_fail2ban() {
    log "Installing and configuring Fail2Ban..."
    install_package "fail2ban" || return 1
    
    # Create local configuration
    if [ -f /etc/fail2ban/jail.conf ]; then
        sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local || log_warning "Failed to create Fail2Ban local config"
    fi
    
    # Configure Fail2Ban settings
    sudo sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local 2>/dev/null || log_warning "Failed to set Fail2Ban bantime"
    sudo sed -i 's/maxretry = 5/maxretry = 3/' /etc/fail2ban/jail.local 2>/dev/null || log_warning "Failed to set Fail2Ban maxretry"
    
    # Enable and start service
    sudo systemctl enable fail2ban || log_warning "Failed to enable Fail2Ban service"
    sudo systemctl restart fail2ban || log_warning "Failed to restart Fail2Ban service"
    
    log "Fail2Ban configured and started"
}

################################################################################
# Antivirus
################################################################################

setup_clamav() {
    log "Installing and updating ClamAV..."
    install_package "clamav" || return 1
    install_package "clamav-daemon" || return 1
    
    # Stop freshclam to update database
    sudo systemctl stop clamav-freshclam 2>/dev/null
    
    # Update virus database
    sudo freshclam 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || log_warning "ClamAV database update failed"
    
    # Start and enable services
    sudo systemctl start clamav-freshclam || log_warning "Failed to start clamav-freshclam"
    sudo systemctl enable clamav-freshclam || log_warning "Failed to enable clamav-freshclam"
    
    log "ClamAV installed and updated"
}

################################################################################
# Access Control
################################################################################

disable_root() {
    log "Checking for non-root sudo users..."
    
    # Get non-root sudo users
    local sudo_users=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v "^root$" | grep -v "^$")
    
    # Verify at least one non-root sudo user exists
    if [ -z "$sudo_users" ]; then
        log_warning "No non-root users with sudo privileges found. Skipping root login disable for safety."
        echo "Please create a non-root user with sudo privileges before disabling root login."
        return 1
    fi
    
    log "Non-root sudo users found: $(echo $sudo_users | tr '\n' ' ')"
    
    # Confirm before proceeding
    read -p "Do you want to disable root login? (y/N): " disable_root_confirm
    if [[ ! "$disable_root_confirm" =~ ^[Yy]$ ]]; then
        log "Skipping root login disable"
        return 0
    fi
    
    # Lock root account
    sudo passwd -l root && log "Root account locked" || handle_error "Failed to lock root account"
    
    # Disable root SSH login
    if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    else
        echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config > /dev/null
    fi
    
    sudo systemctl restart sshd || sudo systemctl restart ssh || log_warning "Failed to restart SSH service"
    
    log "Root login disabled successfully"
}

################################################################################
# Package Management
################################################################################

remove_packages() {
    log "Removing unnecessary and insecure packages..."
    
    local packages_to_remove=(
        "telnetd"
        "nis"
        "yp-tools"
        "rsh-client"
        "rsh-redone-client"
        "xinetd"
        "talk"
        "talkd"
    )
    
    for package in "${packages_to_remove[@]}"; do
        if dpkg -l | grep -qw "$package"; then
            sudo DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "$package" 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null
            log "Removed package: $package"
        fi
    done
    
    sudo apt-get autoremove -y 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null
    log "Package cleanup completed"
}

################################################################################
# Auditing
################################################################################

setup_audit() {
    log "Configuring audit rules..."
    install_package "auditd" || return 1
    
    # Backup existing rules
    [ -f /etc/audit/rules.d/audit.rules ] && sudo cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.bak
    
    # Create comprehensive audit rules
    sudo tee /etc/audit/rules.d/hardening.rules > /dev/null << 'EOF'
## Audit rules for system hardening

# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (0=silent 1=printk 2=panic)
-f 1

# Identity Changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Sudoers Changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Authentication Events
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

# Kernel Module Loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Session Events
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Time Changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Network Configuration
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_config

# System Startup Scripts
-w /etc/rc.d/init.d/ -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init
-w /etc/systemd/ -p wa -k init

# File Deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete

# Make configuration immutable
-e 2
EOF

    # Restart auditd to apply new rules
    sudo systemctl enable auditd || log_warning "Failed to enable auditd"
    sudo systemctl restart auditd || log_warning "Failed to restart auditd"
    
    log "Audit rules configured and auditd started"
}

################################################################################
# Filesystem Security
################################################################################

disable_filesystems() {
    log "Disabling unused filesystems..."
    
    local filesystems=(
        "cramfs"
        "freevxfs"
        "jffs2"
        "hfs"
        "hfsplus"
        "squashfs"
        "udf"
        "vfat"
        "usb-storage"
    )
    
    sudo mkdir -p /etc/modprobe.d
    
    for fs in "${filesystems[@]}"; do
        echo "install $fs /bin/true" | sudo tee -a /etc/modprobe.d/hardening.conf > /dev/null
    done
    
    log "Unused filesystems disabled"
}

secure_filesystem_mounts() {
    log "Securing filesystem mount options..."
    
    # Note: This is informational. Actual /etc/fstab modifications require careful planning
    log_warning "Review and manually update /etc/fstab with secure mount options:"
    log_warning "  - /tmp: nodev,nosuid,noexec"
    log_warning "  - /var/tmp: nodev,nosuid,noexec"
    log_warning "  - /dev/shm: nodev,nosuid,noexec"
    log_warning "  - /home: nodev,nosuid (if separate partition)"
}

################################################################################
# Boot Security
################################################################################

secure_boot() {
    log "Securing boot settings..."
    
    # Secure GRUB configuration file
    if [ -f /boot/grub/grub.cfg ]; then
        sudo chown root:root /boot/grub/grub.cfg || log_warning "Failed to change ownership of grub.cfg"
        sudo chmod 600 /boot/grub/grub.cfg || log_warning "Failed to change permissions of grub.cfg"
        log "GRUB configuration file secured"
    else
        log_warning "/boot/grub/grub.cfg not found"
    fi
    
    # Modify kernel parameters
    if [ -f /etc/default/grub ]; then
        sudo cp /etc/default/grub /etc/default/grub.bak || log_warning "Failed to backup grub file"
        
        local kernel_params="audit=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.send_redirects=0"
        
        # Ask about TCP SACK
        read -p "Do you want to disable TCP SACK? (NOT recommended for most systems) (y/N): " disable_sack
        if [[ "$disable_sack" =~ ^[Yy]$ ]]; then
            kernel_params+=" net.ipv4.tcp_sack=0"
            log "TCP SACK will be disabled"
        fi
        
        # Update GRUB_CMDLINE_LINUX
        if grep -q "^GRUB_CMDLINE_LINUX=" /etc/default/grub; then
            sudo sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$kernel_params\"|" /etc/default/grub
        else
            echo "GRUB_CMDLINE_LINUX=\"$kernel_params\"" | sudo tee -a /etc/default/grub > /dev/null
        fi
        
        # Update GRUB
        if command -v update-grub &> /dev/null; then
            sudo update-grub 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to update GRUB"
        elif command -v grub2-mkconfig &> /dev/null; then
            sudo grub2-mkconfig -o /boot/grub2/grub.cfg 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to update GRUB"
        else
            log_warning "Neither update-grub nor grub2-mkconfig found"
        fi
        
        log "Kernel parameters updated"
    else
        log_warning "/etc/default/grub not found"
    fi
}

################################################################################
# Network Configuration
################################################################################

configure_ipv6() {
    read -p "Do you want to disable IPv6? (y/N): " disable_ipv6
    if [[ "$disable_ipv6" =~ ^[Yy]$ ]]; then
        log "Disabling IPv6..."
        
        # Add IPv6 disable parameters
        sudo tee -a /etc/sysctl.conf > /dev/null << EOF

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        
        sudo sysctl -p 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to apply sysctl changes"
        log "IPv6 disabled"
    else
        log "IPv6 remains enabled"
    fi
}

configure_sysctl() {
    log "Configuring kernel parameters via sysctl..."
    
    # Backup existing sysctl.conf
    sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak 2>/dev/null
    
    # Add comprehensive security settings
    sudo tee -a /etc/sysctl.conf > /dev/null << 'EOF'

################################################################################
# Security Hardening Configuration
################################################################################

# IP Spoofing Protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP Broadcast Requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable Source Packet Routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore Send Redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN Attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martian Packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP Redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed Pings
net.ipv4.icmp_echo_ignore_all = 0

# Enable TCP/IP SYN Cookies
net.ipv4.tcp_syncookies = 1

# Enable Address Space Layout Randomization (ASLR)
kernel.randomize_va_space = 2

# Increase System File Descriptor Limit
fs.file-max = 65535

# Allow for More PIDs
kernel.pid_max = 65536

# Protect Against Kernel Pointer Leaks
kernel.kptr_restrict = 2

# Restrict Access to Kernel Logs
kernel.dmesg_restrict = 1

# Restrict Kernel Profiling
kernel.perf_event_paranoid = 3

# Enable ExecShield
kernel.exec-shield = 1

# Prevent Core Dumps for SUID Programs
fs.suid_dumpable = 0

# Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

EOF

    # Apply sysctl changes
    sudo sysctl -p 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || handle_error "Failed to apply sysctl changes"
    
    log "Kernel parameters configured"
}

################################################################################
# Mandatory Access Control
################################################################################

setup_apparmor() {
    log "Setting up AppArmor..."
    
    # Install AppArmor if not present
    if ! command -v apparmor_status &> /dev/null; then
        install_package "apparmor" || return 1
        install_package "apparmor-utils" || return 1
    else
        log "AppArmor already installed"
    fi

    # Enable and start AppArmor
    sudo systemctl enable apparmor || log_warning "Failed to enable AppArmor service"
    sudo systemctl start apparmor || log_warning "Failed to start AppArmor service"

    # Set profiles to enforce mode
    if [ -d /etc/apparmor.d ]; then
        sudo aa-enforce /etc/apparmor.d/* 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || log_warning "Some AppArmor profiles failed to enforce"
    fi

    log "AppArmor setup complete"
    log "Monitor /var/log/syslog and /var/log/auth.log for AppArmor events"
}

################################################################################
# Time Synchronization
################################################################################

setup_ntp() {
    log "Setting up time synchronization..."
    
    # Prefer systemd-timesyncd on modern systems
    if systemctl list-unit-files 2>/dev/null | grep -q systemd-timesyncd.service; then
        log "Using systemd-timesyncd for time synchronization"
        sudo systemctl enable systemd-timesyncd.service || log_warning "Failed to enable systemd-timesyncd"
        sudo systemctl start systemd-timesyncd.service || log_warning "Failed to start systemd-timesyncd"
        log "systemd-timesyncd configured"
    else
        log "Using traditional NTP"
        install_package "ntp" || return 1
        sudo systemctl enable ntp || log_warning "Failed to enable NTP"
        sudo systemctl start ntp || log_warning "Failed to start NTP"
        log "NTP configured"
    fi
}

################################################################################
# File Integrity Monitoring
################################################################################

setup_aide() {
    log "Setting up AIDE (Advanced Intrusion Detection Environment)..."
    install_package "aide" || return 1
    
    log "Initializing AIDE database (this may take several minutes)..."
    sudo aideinit 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null || handle_error "Failed to initialize AIDE database"
    
    if [ -f /var/lib/aide/aide.db.new ]; then
        sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || handle_error "Failed to move AIDE database"
        log "AIDE database initialized successfully"
        log "Run 'sudo aide --check' to check for file integrity"
    else
        log_warning "AIDE database file not found after initialization"
    fi
}

################################################################################
# SSH Hardening
################################################################################

harden_ssh() {
    log "Hardening SSH configuration..."
    
    # Backup SSH config
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Apply SSH hardening settings
    local ssh_settings=(
        "PermitRootLogin:no"
        "PasswordAuthentication:no"
        "PermitEmptyPasswords:no"
        "X11Forwarding:no"
        "MaxAuthTries:3"
        "ClientAliveInterval:300"
        "ClientAliveCountMax:0"
        "Protocol:2"
        "LogLevel:VERBOSE"
        "UsePAM:yes"
        "AllowTcpForwarding:no"
        "MaxSessions:2"
    )
    
    for setting in "${ssh_settings[@]}"; do
        local key="${setting%%:*}"
        local value="${setting##*:}"
        
        if grep -q "^#*${key}" /etc/ssh/sshd_config; then
            sudo sed -i "s/^#*${key}.*/${key} ${value}/" /etc/ssh/sshd_config
        else
            echo "${key} ${value}" | sudo tee -a /etc/ssh/sshd_config > /dev/null
        fi
    done
    
    # Restart SSH
    sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh || log_warning "Failed to restart SSH"
    
    log "SSH hardening completed"
}

################################################################################
# Additional Security Measures
################################################################################

additional_security() {
    log "Applying additional security measures..."
    
    # Disable core dumps
    echo "* hard core 0" | sudo tee -a /etc/security/limits.conf > /dev/null || log_warning "Failed to disable core dumps"
    
    # Set proper permissions on sensitive files
    sudo chmod 600 /etc/shadow 2>/dev/null || log_warning "Failed to set permissions on /etc/shadow"
    sudo chmod 600 /etc/gshadow 2>/dev/null || log_warning "Failed to set permissions on /etc/gshadow"
    sudo chmod 644 /etc/passwd 2>/dev/null || log_warning "Failed to set permissions on /etc/passwd"
    sudo chmod 644 /etc/group 2>/dev/null || log_warning "Failed to set permissions on /etc/group"
    
    # Enable process accounting
    if install_package "acct"; then
        sudo /usr/sbin/accton on 2>/dev/null || log_warning "Failed to enable process accounting"
        log "Process accounting enabled"
    fi
    
    # Configure password policy
    sudo sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs 2>/dev/null || log_warning "Failed to set PASS_MAX_DAYS"
    sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs 2>/dev/null || log_warning "Failed to set PASS_MIN_DAYS"
    sudo sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t14/' /etc/login.defs 2>/dev/null || log_warning "Failed to set PASS_WARN_AGE"
    
    # Set password quality requirements
    if [ -f /etc/pam.d/common-password ]; then
        if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            install_package "libpam-pwquality"
        fi
        
        # Configure strong password requirements
        sudo sed -i 's/password.*pam_unix.so.*/password    [success=1 default=ignore]    pam_unix.so obscure sha512 minlen=12 remember=5/' /etc/pam.d/common-password 2>/dev/null
        
        # Add pwquality requirements
        if [ -f /etc/security/pwquality.conf ]; then
            sudo tee -a /etc/security/pwquality.conf > /dev/null << EOF

# Password Quality Requirements
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
        fi
    fi
    
    log "Additional security measures applied"
}

################################################################################
# Automatic Updates
################################################################################

setup_automatic_updates() {
    log "Setting up automatic security updates..."
    install_package "unattended-upgrades" || return 1
    install_package "apt-listchanges" || return 1
    
    # Configure unattended-upgrades
    sudo dpkg-reconfigure -plow unattended-upgrades 2>&1 | sudo tee -a "$LOG_FILE" >/dev/null
    
    # Enable automatic security updates only
    if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
        sudo sed -i 's|//Unattended-Upgrade::Mail "";|Unattended-Upgrade::Mail "root";|' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null
    fi
    
    log "Automatic security updates configured"
}

################################################################################
# Security Report Generation
################################################################################

generate_security_report() {
    log "Generating security hardening report..."
    
    local report_file="/root/security_hardening_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=========================================="
        echo "Security Hardening Report"
        echo "Generated: $(date)"
        echo "=========================================="
        echo ""
        echo "System Information:"
        echo "  OS: $(lsb_release -d | cut -f2)"
        echo "  Kernel: $(uname -r)"
        echo "  Hostname: $(hostname)"
        echo ""
        echo "Firewall Status:"
        sudo ufw status verbose 2>/dev/null || echo "  UFW not configured"
        echo ""
        echo "SSH Configuration:"
        grep -E "^(PermitRootLogin|PasswordAuthentication|Protocol)" /etc/ssh/sshd_config 2>/dev/null || echo "  SSH config not found"
        echo ""
        echo "Audit Status:"
        sudo systemctl status auditd --no-pager 2>/dev/null | head -5 || echo "  Auditd not running"
        echo ""
        echo "AppArmor Status:"
        sudo aa-status 2>/dev/null | head -10 || echo "  AppArmor not configured"
        echo ""
        echo "Listening Services:"
        sudo ss -tulpn 2>/dev/null || echo "  Unable to list services"
        echo ""
        echo "=========================================="
        echo "Backup Location: $BACKUP_DIR"
        echo "Log File: $LOG_FILE"
        echo "=========================================="
    } | sudo tee "$report_file" > /dev/null
    
    log "Security report generated: $report_file"
}

################################################################################
# Main Function
################################################################################

main() {
    local skip_update=false
    local minimal_mode=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                display_help
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --restore)
                check_permissions
                restore_backup
                exit 0
                ;;
            --skip-update)
                skip_update=true
                shift
                ;;
            --minimal)
                minimal_mode=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                display_help
                ;;
        esac
    done

    # Initialize
    check_permissions
    check_requirements
    
    echo ""
    echo "=========================================="
    echo "Linux Security Hardening Script v2.0"
    echo "=========================================="
    echo ""
    echo "This script will perform comprehensive security hardening."
    echo "A backup will be created at: $BACKUP_DIR"
    echo "Logs will be written to: $LOG_FILE"
    echo ""
    read -p "Do you want to continue? (y/N): " confirm_start
    if [[ ! "$confirm_start" =~ ^[Yy]$ ]]; then
        echo "Aborted by user"
        exit 0
    fi
    
    backup_files

    # Core hardening steps
    if [ "$skip_update" = false ]; then
        update_system
    fi
    
    user_management
    setup_firewall
    harden_ssh
    disable_root
    remove_packages
    setup_audit
    disable_filesystems
    secure_filesystem_mounts
    secure_boot
    configure_ipv6
    configure_sysctl
    additional_security
    
    # Optional components (skip in minimal mode)
    if [ "$minimal_mode" = false ]; then
        setup_suricata
        setup_fail2ban
        setup_clamav
        setup_apparmor
        setup_ntp
        setup_aide
        setup_automatic_updates
    else
        log "Minimal mode: Skipping optional components"
    fi
    
    generate_security_report
    
    echo ""
    log "=========================================="
    log "Security hardening completed successfully!"
    log "=========================================="
    log "Backup: $BACKUP_DIR"
    log "Log: $LOG_FILE"
    echo ""
    
    read -p "Do you want to restart the system now? (y/N): " restart_now
    case $restart_now in
        [Yy]* ) 
            log "Restarting system..."
            sudo reboot
            ;;
        * ) 
            echo ""
            echo "Please restart your system manually to apply all changes."
            echo ""
            ;;
    esac
}

################################################################################
# Script Entry Point
################################################################################

# Run the main function with all arguments
main "$@"