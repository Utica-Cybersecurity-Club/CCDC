#!/bin/bash

################################################################################
# Universal Linux Security Hardening Script
# Version: 3.0 - Multi-Distribution Support
# Compatible with: Ubuntu, Debian, RHEL, Rocky, AlmaLinux, Alpine, Arch
################################################################################

# Global variables
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/hardening.log"
SCRIPT_NAME=$(basename "$0")
VERBOSE=false

# Distribution detection variables
DISTRO=""
DISTRO_FAMILY=""
PKG_MANAGER=""
PKG_INSTALL=""
PKG_REMOVE=""
PKG_UPDATE=""
PKG_UPGRADE=""
SERVICE_MANAGER=""
FIREWALL_TOOL=""

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Distribution Detection
################################################################################

detect_distribution() {
    log "Detecting distribution..."
    
    # Check for OS release file
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
        DISTRO_PRETTY="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        DISTRO_VERSION=$(cat /etc/redhat-release | grep -oE '[0-9]+\.[0-9]+' | head -1)
        DISTRO_PRETTY=$(cat /etc/redhat-release)
    elif [ -f /etc/alpine-release ]; then
        DISTRO="alpine"
        DISTRO_VERSION=$(cat /etc/alpine-release)
        DISTRO_PRETTY="Alpine Linux $DISTRO_VERSION"
    else
        log_error "Unable to detect distribution"
        return 1
    fi
    
    # Determine distribution family
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop)
            DISTRO_FAMILY="debian"
            PKG_MANAGER="apt"
            PKG_INSTALL="apt-get install -y"
            PKG_REMOVE="apt-get remove --purge -y"
            PKG_UPDATE="apt-get update -y"
            PKG_UPGRADE="apt-get upgrade -y"
            SERVICE_MANAGER="systemd"
            FIREWALL_TOOL="ufw"
            ;;
        rhel|centos|rocky|almalinux|ol|fedora)
            DISTRO_FAMILY="rhel"
            PKG_MANAGER="dnf"
            # Fallback to yum for older systems
            if ! command -v dnf &> /dev/null && command -v yum &> /dev/null; then
                PKG_MANAGER="yum"
            fi
            PKG_INSTALL="$PKG_MANAGER install -y"
            PKG_REMOVE="$PKG_MANAGER remove -y"
            PKG_UPDATE="$PKG_MANAGER check-update"
            PKG_UPGRADE="$PKG_MANAGER upgrade -y"
            SERVICE_MANAGER="systemd"
            FIREWALL_TOOL="firewalld"
            ;;
        alpine)
            DISTRO_FAMILY="alpine"
            PKG_MANAGER="apk"
            PKG_INSTALL="apk add"
            PKG_REMOVE="apk del"
            PKG_UPDATE="apk update"
            PKG_UPGRADE="apk upgrade"
            SERVICE_MANAGER="openrc"
            FIREWALL_TOOL="iptables"
            ;;
        arch|manjaro|endeavouros)
            DISTRO_FAMILY="arch"
            PKG_MANAGER="pacman"
            PKG_INSTALL="pacman -S --noconfirm"
            PKG_REMOVE="pacman -Rns --noconfirm"
            PKG_UPDATE="pacman -Sy"
            PKG_UPGRADE="pacman -Syu --noconfirm"
            SERVICE_MANAGER="systemd"
            FIREWALL_TOOL="ufw"
            ;;
        opensuse*|sles)
            DISTRO_FAMILY="suse"
            PKG_MANAGER="zypper"
            PKG_INSTALL="zypper install -y"
            PKG_REMOVE="zypper remove -y"
            PKG_UPDATE="zypper refresh"
            PKG_UPGRADE="zypper update -y"
            SERVICE_MANAGER="systemd"
            FIREWALL_TOOL="firewalld"
            ;;
        *)
            log_warning "Unknown distribution: $DISTRO"
            log_warning "Attempting to detect package manager..."
            
            if command -v apt-get &> /dev/null; then
                DISTRO_FAMILY="debian"
                PKG_MANAGER="apt"
                FIREWALL_TOOL="ufw"
            elif command -v dnf &> /dev/null; then
                DISTRO_FAMILY="rhel"
                PKG_MANAGER="dnf"
                FIREWALL_TOOL="firewalld"
            elif command -v yum &> /dev/null; then
                DISTRO_FAMILY="rhel"
                PKG_MANAGER="yum"
                FIREWALL_TOOL="firewalld"
            elif command -v apk &> /dev/null; then
                DISTRO_FAMILY="alpine"
                PKG_MANAGER="apk"
                FIREWALL_TOOL="iptables"
            elif command -v pacman &> /dev/null; then
                DISTRO_FAMILY="arch"
                PKG_MANAGER="pacman"
                FIREWALL_TOOL="ufw"
            elif command -v zypper &> /dev/null; then
                DISTRO_FAMILY="suse"
                PKG_MANAGER="zypper"
                FIREWALL_TOOL="firewalld"
            else
                log_error "Unable to detect package manager"
                return 1
            fi
            
            # Set install/remove commands based on detected package manager
            case "$PKG_MANAGER" in
                apt)
                    PKG_INSTALL="apt-get install -y"
                    PKG_REMOVE="apt-get remove --purge -y"
                    PKG_UPDATE="apt-get update -y"
                    PKG_UPGRADE="apt-get upgrade -y"
                    ;;
                dnf|yum)
                    PKG_INSTALL="$PKG_MANAGER install -y"
                    PKG_REMOVE="$PKG_MANAGER remove -y"
                    PKG_UPDATE="$PKG_MANAGER check-update"
                    PKG_UPGRADE="$PKG_MANAGER upgrade -y"
                    ;;
                apk)
                    PKG_INSTALL="apk add"
                    PKG_REMOVE="apk del"
                    PKG_UPDATE="apk update"
                    PKG_UPGRADE="apk upgrade"
                    ;;
                pacman)
                    PKG_INSTALL="pacman -S --noconfirm"
                    PKG_REMOVE="pacman -Rns --noconfirm"
                    PKG_UPDATE="pacman -Sy"
                    PKG_UPGRADE="pacman -Syu --noconfirm"
                    ;;
                zypper)
                    PKG_INSTALL="zypper install -y"
                    PKG_REMOVE="zypper remove -y"
                    PKG_UPDATE="zypper refresh"
                    PKG_UPGRADE="zypper update -y"
                    ;;
            esac
            
            SERVICE_MANAGER="systemd"
            ;;
    esac
    
    # Detect service manager if not already set
    if [ -z "$SERVICE_MANAGER" ]; then
        if command -v systemctl &> /dev/null; then
            SERVICE_MANAGER="systemd"
        elif command -v rc-service &> /dev/null; then
            SERVICE_MANAGER="openrc"
        elif command -v service &> /dev/null; then
            SERVICE_MANAGER="sysvinit"
        else
            SERVICE_MANAGER="systemd"  # Default assumption
        fi
    fi
    
    log "Detected: $DISTRO_PRETTY"
    log "Distribution Family: $DISTRO_FAMILY"
    log "Package Manager: $PKG_MANAGER"
    log "Service Manager: $SERVICE_MANAGER"
    log "Firewall Tool: $FIREWALL_TOOL"
    
    return 0
}

################################################################################
# Core Functions
################################################################################

# Function for logging
log() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): $1"
    echo "$message" | tee -a "$LOG_FILE" 2>/dev/null || echo "$message" >> "$LOG_FILE"
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): WARNING: $1"
    echo "$message" | tee -a "$LOG_FILE" 2>/dev/null || echo "$message" >> "$LOG_FILE"
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): ERROR: $1"
    echo "$message" | tee -a "$LOG_FILE" 2>/dev/null || echo "$message" >> "$LOG_FILE"
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    local message="=== $1 ==="
    echo "$message" | tee -a "$LOG_FILE" 2>/dev/null || echo "$message" >> "$LOG_FILE"
    echo -e "${BLUE}${message}${NC}"
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

# Service management wrapper
service_enable() {
    local service_name="$1"
    case "$SERVICE_MANAGER" in
        systemd)
            systemctl enable "$service_name" 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        openrc)
            rc-update add "$service_name" default 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        sysvinit)
            chkconfig "$service_name" on 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
    esac
}

service_start() {
    local service_name="$1"
    case "$SERVICE_MANAGER" in
        systemd)
            systemctl start "$service_name" 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        openrc)
            rc-service "$service_name" start 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        sysvinit)
            service "$service_name" start 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
    esac
}

service_restart() {
    local service_name="$1"
    case "$SERVICE_MANAGER" in
        systemd)
            systemctl restart "$service_name" 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        openrc)
            rc-service "$service_name" restart 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        sysvinit)
            service "$service_name" restart 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
    esac
}

service_stop() {
    local service_name="$1"
    case "$SERVICE_MANAGER" in
        systemd)
            systemctl stop "$service_name" 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        openrc)
            rc-service "$service_name" stop 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        sysvinit)
            service "$service_name" stop 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
    esac
}

# Function to install packages
install_package() {
    local package="$1"
    
    # Check if package is already installed based on package manager
    case "$PKG_MANAGER" in
        apt)
            if dpkg -l | grep -qw "$package"; then
                log "Package $package is already installed"
                return 0
            fi
            DEBIAN_FRONTEND=noninteractive $PKG_INSTALL "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        dnf|yum)
            if rpm -q "$package" &>/dev/null; then
                log "Package $package is already installed"
                return 0
            fi
            $PKG_INSTALL "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        apk)
            if apk info -e "$package" &>/dev/null; then
                log "Package $package is already installed"
                return 0
            fi
            $PKG_INSTALL "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        pacman)
            if pacman -Q "$package" &>/dev/null; then
                log "Package $package is already installed"
                return 0
            fi
            $PKG_INSTALL "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        zypper)
            if rpm -q "$package" &>/dev/null; then
                log "Package $package is already installed"
                return 0
            fi
            $PKG_INSTALL "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        log "Successfully installed $package"
        return 0
    else
        handle_error "Failed to install $package"
        return 1
    fi
}

# Function to backup files
backup_files() {
    log "Creating backup directory..."
    mkdir -p "$BACKUP_DIR" || handle_error "Failed to create backup directory"
    
    local files_to_backup=(
        "/etc/ssh/sshd_config"
        "/etc/sysctl.conf"
        "/etc/security/limits.conf"
        "/etc/fstab"
    )
    
    # Add distribution-specific files
    case "$DISTRO_FAMILY" in
        debian)
            files_to_backup+=(
                "/etc/default/grub"
                "/etc/pam.d/common-password"
                "/etc/login.defs"
            )
            ;;
        rhel|suse)
            files_to_backup+=(
                "/etc/default/grub"
                "/etc/login.defs"
                "/etc/pam.d/system-auth"
                "/etc/pam.d/password-auth"
            )
            ;;
        alpine)
            files_to_backup+=(
                "/etc/pam.d/base-password"
                "/etc/login.defs"
            )
            ;;
        arch)
            files_to_backup+=(
                "/etc/default/grub"
                "/etc/pam.d/passwd"
                "/etc/login.defs"
            )
            ;;
    esac
    
    for file in "${files_to_backup[@]}"; do
        if [ -f "$file" ]; then
            cp -a "$file" "$BACKUP_DIR/" && log "Backed up $file" || log_warning "Failed to backup $file"
        else
            log_warning "$file not found, skipping backup"
        fi
    done
    
    log "Backup created in $BACKUP_DIR"
}

# Function to check permissions
check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}This script must be run with root privileges.${NC}"
        echo "Please run it again using: sudo $0"
        exit 1
    fi
}

# Function to display help
display_help() {
    cat << EOF
Usage: sudo ./$SCRIPT_NAME [OPTIONS]

Universal Linux Security Hardening Script
Supports: Ubuntu, Debian, RHEL, Rocky, AlmaLinux, Alpine, Arch, openSUSE

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
    
    detect_distribution || handle_error "Failed to detect distribution"
    
    # Check for minimum version requirements
    case "$DISTRO_FAMILY" in
        debian)
            if [[ "$DISTRO" == "ubuntu" ]]; then
                local major_version=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
                if [[ $major_version -lt 18 ]]; then
                    handle_error "This script requires Ubuntu 18.04 or later. Detected version: $DISTRO_VERSION"
                    return 1
                fi
            elif [[ "$DISTRO" == "debian" ]]; then
                local major_version=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
                if [[ $major_version -lt 10 ]]; then
                    handle_error "This script requires Debian 10 or later. Detected version: $DISTRO_VERSION"
                    return 1
                fi
            fi
            ;;
        rhel)
            local major_version=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
            if [[ $major_version -lt 7 ]]; then
                handle_error "This script requires RHEL/Rocky/AlmaLinux 7 or later. Detected version: $DISTRO_VERSION"
                return 1
            fi
            ;;
        alpine)
            local major_version=$(echo "$DISTRO_VERSION" | cut -d'.' -f1)
            if [[ $major_version -lt 3 ]]; then
                handle_error "This script requires Alpine 3.x or later. Detected version: $DISTRO_VERSION"
                return 1
            fi
            ;;
    esac

    log "System requirements check passed."
}

# Function to update system
update_system() {
    log_section "Updating System Packages"
    
    case "$PKG_MANAGER" in
        apt)
            DEBIAN_FRONTEND=noninteractive $PKG_UPDATE 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "System update failed"
            DEBIAN_FRONTEND=noninteractive $PKG_UPGRADE 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "System upgrade failed"
            ;;
        dnf|yum)
            $PKG_UPDATE 2>&1 | tee -a "$LOG_FILE" >/dev/null
            $PKG_UPGRADE 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "System upgrade failed"
            ;;
        apk)
            $PKG_UPDATE 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "System update failed"
            $PKG_UPGRADE 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "System upgrade failed"
            ;;
        pacman)
            $PKG_UPDATE 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "System update failed"
            $PKG_UPGRADE 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "System upgrade failed"
            ;;
        zypper)
            $PKG_UPDATE 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "System update failed"
            $PKG_UPGRADE 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "System upgrade failed"
            ;;
    esac
    
    log "System update completed"
}

################################################################################
# User Management
################################################################################

user_management() {
    log_section "User Management"
    
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
    
    # Change passwords
    echo "$actual_user:$ADMIN_PASS" | chpasswd || log_warning "Failed to change password for $actual_user"
    echo "root:$ROOT_PASS" | chpasswd || log_warning "Failed to change root password"
    
    log "Passwords updated"
}

################################################################################
# Firewall Configuration
################################################################################

setup_firewall() {
    log_section "Configuring Firewall"
    
    case "$FIREWALL_TOOL" in
        ufw)
            setup_firewall_ufw
            ;;
        firewalld)
            setup_firewall_firewalld
            ;;
        iptables)
            setup_firewall_iptables
            ;;
        *)
            log_warning "Unknown firewall tool: $FIREWALL_TOOL"
            ;;
    esac
}

setup_firewall_ufw() {
    log "Installing and configuring UFW firewall..."
    install_package "ufw" || return 1
    
    # Reset UFW to default state
    ufw --force reset 2>&1 | tee -a "$LOG_FILE" >/dev/null
    
    # Set default policies
    ufw default deny incoming || handle_error "Failed to set UFW default incoming policy"
    ufw default allow outgoing || handle_error "Failed to set UFW default outgoing policy"
    
    # Allow essential services
    ufw limit ssh comment 'SSH with rate limiting' || handle_error "Failed to configure SSH in UFW"
    
    # Ask about web services
    read -p "Do you want to allow HTTP/HTTPS traffic? (Y/n): " allow_web
    if [[ ! "$allow_web" =~ ^[Nn]$ ]]; then
        ufw allow 80/tcp comment 'HTTP' || log_warning "Failed to allow HTTP"
        ufw allow 443/tcp comment 'HTTPS' || log_warning "Failed to allow HTTPS"
    fi
    
    # Enable logging
    ufw logging on || log_warning "Failed to enable UFW logging"
    
    # Enable firewall
    ufw --force enable || handle_error "Failed to enable UFW"
    
    log "UFW firewall configured and enabled"
    ufw status verbose | tee -a "$LOG_FILE"
}

setup_firewall_firewalld() {
    log "Installing and configuring firewalld..."
    
    # Install firewalld
    case "$DISTRO_FAMILY" in
        rhel|suse)
            install_package "firewalld" || return 1
            ;;
    esac
    
    # Enable and start firewalld
    service_enable firewalld || log_warning "Failed to enable firewalld"
    service_start firewalld || handle_error "Failed to start firewalld"
    
    # Set default zone to drop (more restrictive)
    firewall-cmd --set-default-zone=drop 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to set default zone"
    
    # Create a custom zone for allowed services
    firewall-cmd --permanent --new-zone=hardened 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "Zone may already exist"
    firewall-cmd --permanent --zone=hardened --set-target=DROP 2>&1 | tee -a "$LOG_FILE" >/dev/null
    
    # Allow SSH in hardened zone
    firewall-cmd --permanent --zone=hardened --add-service=ssh 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to add SSH"
    
    # Ask about web services
    read -p "Do you want to allow HTTP/HTTPS traffic? (Y/n): " allow_web
    if [[ ! "$allow_web" =~ ^[Nn]$ ]]; then
        firewall-cmd --permanent --zone=hardened --add-service=http 2>&1 | tee -a "$LOG_FILE" >/dev/null
        firewall-cmd --permanent --zone=hardened --add-service=https 2>&1 | tee -a "$LOG_FILE" >/dev/null
    fi
    
    # Add interface to hardened zone (get primary interface)
    local primary_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$primary_interface" ]; then
        firewall-cmd --permanent --zone=hardened --add-interface="$primary_interface" 2>&1 | tee -a "$LOG_FILE" >/dev/null
        log "Added interface $primary_interface to hardened zone"
    fi
    
    # Reload firewall
    firewall-cmd --reload 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "Failed to reload firewalld"
    
    log "Firewalld configured and enabled"
    firewall-cmd --list-all-zones | tee -a "$LOG_FILE"
}

setup_firewall_iptables() {
    log "Configuring iptables firewall..."
    
    # Install iptables
    case "$DISTRO_FAMILY" in
        alpine)
            install_package "iptables" || return 1
            ;;
    esac
    
    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH with rate limiting
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Ask about web services
    read -p "Do you want to allow HTTP/HTTPS traffic? (Y/n): " allow_web
    if [[ ! "$allow_web" =~ ^[Nn]$ ]]; then
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    fi
    
    # Drop invalid packets
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    
    # Save iptables rules based on distribution
    case "$DISTRO_FAMILY" in
        alpine)
            # Save iptables rules for Alpine
            rc-update add iptables 2>&1 | tee -a "$LOG_FILE" >/dev/null
            /etc/init.d/iptables save 2>&1 | tee -a "$LOG_FILE" >/dev/null || {
                # Alternative method for Alpine
                iptables-save > /etc/iptables/rules-save 2>&1 | tee -a "$LOG_FILE" >/dev/null
            }
            ;;
        debian)
            install_package "iptables-persistent"
            iptables-save > /etc/iptables/rules.v4 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        rhel)
            install_package "iptables-services"
            service iptables save 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
    esac
    
    log "Iptables firewall configured"
    iptables -L -v -n | tee -a "$LOG_FILE"
}

################################################################################
# Intrusion Detection/Prevention
################################################################################

setup_fail2ban() {
    log_section "Installing Fail2Ban"
    
    # Install fail2ban based on distribution
    case "$DISTRO_FAMILY" in
        debian|arch)
            install_package "fail2ban" || return 1
            ;;
        rhel)
            # Enable EPEL repository for RHEL-based systems
            if [[ "$DISTRO" == "rhel" ]] || [[ "$DISTRO" == "centos" ]]; then
                install_package "epel-release" || log_warning "EPEL repository may already be installed"
            fi
            install_package "fail2ban" || return 1
            ;;
        alpine)
            install_package "fail2ban" || return 1
            ;;
        suse)
            install_package "fail2ban" || return 1
            ;;
    esac
    
    # Create local configuration
    local jail_conf=""
    case "$DISTRO_FAMILY" in
        alpine)
            jail_conf="/etc/fail2ban/jail.local"
            ;;
        *)
            jail_conf="/etc/fail2ban/jail.local"
            if [ -f /etc/fail2ban/jail.conf ]; then
                cp /etc/fail2ban/jail.conf "$jail_conf" || log_warning "Failed to create Fail2Ban local config"
            fi
            ;;
    esac
    
    # Configure Fail2Ban settings
    if [ -f "$jail_conf" ]; then
        sed -i 's/bantime  = 10m/bantime  = 1h/' "$jail_conf" 2>/dev/null || log_warning "Failed to set Fail2Ban bantime"
        sed -i 's/maxretry = 5/maxretry = 3/' "$jail_conf" 2>/dev/null || log_warning "Failed to set Fail2Ban maxretry"
    else
        # Create basic jail.local
        cat > "$jail_conf" << 'EOF'
[DEFAULT]
bantime  = 1h
maxretry = 3
findtime = 10m

[sshd]
enabled = true
EOF
    fi
    
    # Enable and start service
    service_enable fail2ban || log_warning "Failed to enable Fail2Ban service"
    service_restart fail2ban || log_warning "Failed to restart Fail2Ban service"
    
    log "Fail2Ban configured and started"
}

setup_clamav() {
    log_section "Installing ClamAV"
    
    # Install ClamAV based on distribution
    case "$DISTRO_FAMILY" in
        debian)
            install_package "clamav" || return 1
            install_package "clamav-daemon" || return 1
            
            # Stop freshclam to update database
            service_stop clamav-freshclam 2>/dev/null
            freshclam 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "ClamAV database update failed"
            service_start clamav-freshclam || log_warning "Failed to start clamav-freshclam"
            service_enable clamav-freshclam || log_warning "Failed to enable clamav-freshclam"
            ;;
        rhel)
            # Enable EPEL for ClamAV
            if [[ "$DISTRO" == "rhel" ]] || [[ "$DISTRO" == "centos" ]]; then
                install_package "epel-release" || log_warning "EPEL repository may already be installed"
            fi
            install_package "clamav" || return 1
            install_package "clamav-update" || return 1
            install_package "clamd" || return 1
            
            # Update database
            freshclam 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "ClamAV database update failed"
            ;;
        alpine)
            install_package "clamav" || return 1
            install_package "clamav-daemon" || return 1
            
            freshclam 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "ClamAV database update failed"
            rc-update add clamd 2>&1 | tee -a "$LOG_FILE" >/dev/null
            rc-service clamd start 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        arch)
            install_package "clamav" || return 1
            freshclam 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "ClamAV database update failed"
            service_enable clamav-daemon || log_warning "Failed to enable clamav-daemon"
            service_start clamav-daemon || log_warning "Failed to start clamav-daemon"
            ;;
    esac
    
    log "ClamAV installed and updated"
}

################################################################################
# Access Control
################################################################################

disable_root() {
    log_section "Disabling Root Login"
    
    # Get list of sudo users based on distribution
    local sudo_users=""
    case "$DISTRO_FAMILY" in
        debian|arch)
            sudo_users=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v "^root$" | grep -v "^$")
            ;;
        rhel|alpine|suse)
            sudo_users=$(getent group wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v "^root$" | grep -v "^$")
            ;;
    esac
    
    # Verify at least one non-root sudo user exists
    if [ -z "$sudo_users" ]; then
        log_warning "No non-root users with sudo/wheel privileges found. Skipping root login disable for safety."
        echo "Please create a non-root user with sudo/wheel privileges before disabling root login."
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
    passwd -l root && log "Root account locked" || handle_error "Failed to lock root account"
    
    log "Root login disabled successfully"
}

################################################################################
# Package Management
################################################################################

remove_packages() {
    log_section "Removing Unnecessary Packages"
    
    local packages_to_remove=()
    
    case "$DISTRO_FAMILY" in
        debian)
            packages_to_remove=(
                "telnetd" "nis" "yp-tools" "rsh-client"
                "rsh-redone-client" "xinetd" "talk" "talkd"
            )
            ;;
        rhel)
            packages_to_remove=(
                "telnet-server" "ypbind" "ypserv" "tftp"
                "tftp-server" "talk" "xinetd" "rsh-server"
            )
            ;;
        alpine)
            packages_to_remove=(
                "telnet" "rsh" "talk"
            )
            ;;
        arch)
            packages_to_remove=(
                "telnet" "rsh" "talk"
            )
            ;;
        suse)
            packages_to_remove=(
                "telnet-server" "rsh-server" "talk-server"
            )
            ;;
    esac
    
    for package in "${packages_to_remove[@]}"; do
        case "$PKG_MANAGER" in
            apt)
                if dpkg -l | grep -qw "$package"; then
                    DEBIAN_FRONTEND=noninteractive $PKG_REMOVE "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
                    log "Removed package: $package"
                fi
                ;;
            dnf|yum)
                if rpm -q "$package" &>/dev/null; then
                    $PKG_REMOVE "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
                    log "Removed package: $package"
                fi
                ;;
            apk)
                if apk info -e "$package" &>/dev/null; then
                    $PKG_REMOVE "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
                    log "Removed package: $package"
                fi
                ;;
            pacman)
                if pacman -Q "$package" &>/dev/null; then
                    $PKG_REMOVE "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
                    log "Removed package: $package"
                fi
                ;;
            zypper)
                if rpm -q "$package" &>/dev/null; then
                    $PKG_REMOVE "$package" 2>&1 | tee -a "$LOG_FILE" >/dev/null
                    log "Removed package: $package"
                fi
                ;;
        esac
    done
    
    # Auto-remove orphaned packages
    case "$PKG_MANAGER" in
        apt)
            apt-get autoremove -y 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        dnf|yum)
            $PKG_MANAGER autoremove -y 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        pacman)
            pacman -Rns $(pacman -Qtdq) --noconfirm 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
    esac
    
    log "Package cleanup completed"
}

################################################################################
# Auditing
################################################################################

setup_audit() {
    log_section "Configuring Audit Rules"
    
    # Install audit daemon based on distribution
    case "$DISTRO_FAMILY" in
        debian|arch)
            install_package "auditd" || return 1
            ;;
        rhel|suse)
            install_package "audit" || return 1
            ;;
        alpine)
            log_warning "Auditd not available for Alpine Linux, skipping"
            return 1
            ;;
    esac
    
    # Determine audit rules directory
    local audit_rules_dir="/etc/audit/rules.d"
    if [ ! -d "$audit_rules_dir" ]; then
        audit_rules_dir="/etc/audit"
    fi
    
    # Create comprehensive audit rules
    cat > "$audit_rules_dir/hardening.rules" << 'EOF'
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
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

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
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_config

# File Deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete

# Make configuration immutable
-e 2
EOF

    # Restart audit daemon
    service_enable auditd || log_warning "Failed to enable auditd"
    service_restart auditd || log_warning "Failed to restart auditd"
    
    log "Audit rules configured and auditd started"
}

################################################################################
# Filesystem Security
################################################################################

disable_filesystems() {
    log_section "Disabling Unused Filesystems"
    
    local filesystems=(
        "cramfs" "freevxfs" "jffs2" "hfs" "hfsplus"
        "squashfs" "udf" "vfat" "usb-storage"
    )
    
    # Determine modprobe directory
    local modprobe_dir="/etc/modprobe.d"
    mkdir -p "$modprobe_dir"
    
    for fs in "${filesystems[@]}"; do
        echo "install $fs /bin/true" >> "$modprobe_dir/hardening.conf"
    done
    
    log "Unused filesystems disabled"
}

################################################################################
# Boot Security
################################################################################

secure_boot() {
    log_section "Securing Boot Settings"
    
    # This is primarily for systems using GRUB
    if [ -f /boot/grub/grub.cfg ] || [ -f /boot/grub2/grub.cfg ]; then
        # Secure GRUB configuration file
        local grub_cfg="/boot/grub/grub.cfg"
        [ -f /boot/grub2/grub.cfg ] && grub_cfg="/boot/grub2/grub.cfg"
        
        chown root:root "$grub_cfg" 2>/dev/null || log_warning "Failed to change ownership of grub.cfg"
        chmod 600 "$grub_cfg" 2>/dev/null || log_warning "Failed to change permissions of grub.cfg"
        log "GRUB configuration file secured"
    else
        log_warning "GRUB configuration not found, skipping GRUB hardening"
    fi
    
    # Modify kernel parameters
    local grub_default=""
    if [ -f /etc/default/grub ]; then
        grub_default="/etc/default/grub"
    else
        log_warning "GRUB default file not found, skipping kernel parameters"
        return 0
    fi
    
    # Backup original file
    cp "$grub_default" "${grub_default}.bak" || handle_error "Failed to backup grub file"
    
    # Add kernel parameters
    local kernel_params="audit=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.send_redirects=0"
    
    if grep -q "^GRUB_CMDLINE_LINUX=" "$grub_default"; then
        sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$kernel_params\"|" "$grub_default"
    else
        echo "GRUB_CMDLINE_LINUX=\"$kernel_params\"" >> "$grub_default"
    fi
    
    # Update GRUB based on distribution
    case "$DISTRO_FAMILY" in
        debian|arch)
            if command -v update-grub &> /dev/null; then
                update-grub 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to update GRUB"
            elif command -v grub-mkconfig &> /dev/null; then
                grub-mkconfig -o /boot/grub/grub.cfg 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to update GRUB"
            fi
            ;;
        rhel|suse)
            if command -v grub2-mkconfig &> /dev/null; then
                grub2-mkconfig -o /boot/grub2/grub.cfg 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to update GRUB"
            fi
            ;;
        alpine)
            log_warning "Alpine uses different bootloader, skipping GRUB update"
            ;;
    esac
    
    log "Boot settings secured"
}

################################################################################
# Network Configuration
################################################################################

configure_ipv6() {
    read -p "Do you want to disable IPv6? (y/N): " disable_ipv6
    if [[ "$disable_ipv6" =~ ^[Yy]$ ]]; then
        log_section "Disabling IPv6"
        
        # Add IPv6 disable parameters to sysctl
        tee -a /etc/sysctl.conf > /dev/null << EOF

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        
        sysctl -p 2>&1 | tee -a "$LOG_FILE" >/dev/null || log_warning "Failed to apply sysctl changes"
        log "IPv6 disabled"
    else
        log "IPv6 remains enabled"
    fi
}

configure_sysctl() {
    log_section "Configuring Kernel Parameters"
    
    # Backup existing sysctl.conf
    [ -f /etc/sysctl.conf ] && cp /etc/sysctl.conf /etc/sysctl.conf.bak 2>/dev/null
    
    # Add comprehensive security settings
    tee -a /etc/sysctl.conf > /dev/null << 'EOF'

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

# Prevent Core Dumps for SUID Programs
fs.suid_dumpable = 0

# Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

EOF

    # Apply sysctl changes
    sysctl -p 2>&1 | tee -a "$LOG_FILE" >/dev/null || handle_error "Failed to apply sysctl changes"
    
    log "Kernel parameters configured"
}

################################################################################
# SSH Hardening
################################################################################

harden_ssh() {
    log_section "Hardening SSH Configuration"
    
    local ssh_config="/etc/ssh/sshd_config"
    
    # Backup SSH config
    cp "$ssh_config" "${ssh_config}.bak" || log_warning "Failed to backup SSH config"
    
    # Apply SSH hardening settings
    local ssh_settings=(
        "PermitRootLogin:no"
        "PasswordAuthentication:no"
        "PermitEmptyPasswords:no"
        "X11Forwarding:no"
        "MaxAuthTries:3"
        "ClientAliveInterval:300"
        "ClientAliveCountMax:0"
        "LogLevel:VERBOSE"
        "UsePAM:yes"
        "AllowTcpForwarding:no"
        "MaxSessions:2"
    )
    
    # Only set Protocol 2 for older SSH versions
    if sshd -V 2>&1 | grep -q "OpenSSH_[4-6]"; then
        ssh_settings+=("Protocol:2")
    fi
    
    for setting in "${ssh_settings[@]}"; do
        local key="${setting%%:*}"
        local value="${setting##*:}"
        
        if grep -q "^#*${key}" "$ssh_config"; then
            sed -i "s/^#*${key}.*/${key} ${value}/" "$ssh_config"
        else
            echo "${key} ${value}" >> "$ssh_config"
        fi
    done
    
    # Restart SSH based on distribution
    case "$DISTRO_FAMILY" in
        debian|arch)
            service_restart sshd || service_restart ssh || log_warning "Failed to restart SSH"
            ;;
        rhel|suse)
            service_restart sshd || log_warning "Failed to restart SSH"
            ;;
        alpine)
            service_restart sshd || log_warning "Failed to restart SSH"
            ;;
    esac
    
    log "SSH hardening completed"
}

################################################################################
# Additional Security Measures
################################################################################

additional_security() {
    log_section "Applying Additional Security Measures"
    
    # Disable core dumps
    echo "* hard core 0" >> /etc/security/limits.conf || log_warning "Failed to disable core dumps"
    
    # Set proper permissions on sensitive files
    chmod 600 /etc/shadow 2>/dev/null || log_warning "Failed to set permissions on /etc/shadow"
    chmod 600 /etc/gshadow 2>/dev/null || log_warning "Failed to set permissions on /etc/gshadow"
    chmod 644 /etc/passwd 2>/dev/null || log_warning "Failed to set permissions on /etc/passwd"
    chmod 644 /etc/group 2>/dev/null || log_warning "Failed to set permissions on /etc/group"
    
    # Configure password policy based on distribution
    case "$DISTRO_FAMILY" in
        debian)
            if [ -f /etc/login.defs ]; then
                sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs 2>/dev/null
                sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs 2>/dev/null
                sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t14/' /etc/login.defs 2>/dev/null
            fi
            
            # Install pwquality
            install_package "libpam-pwquality"
            
            if [ -f /etc/security/pwquality.conf ]; then
                tee -a /etc/security/pwquality.conf > /dev/null << EOF

# Password Quality Requirements
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
            fi
            ;;
        rhel|suse)
            if [ -f /etc/login.defs ]; then
                sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs 2>/dev/null
                sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs 2>/dev/null
                sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t14/' /etc/login.defs 2>/dev/null
            fi
            
            # Install pwquality for RHEL
            install_package "libpwquality"
            
            if [ -f /etc/security/pwquality.conf ]; then
                tee -a /etc/security/pwquality.conf > /dev/null << EOF

# Password Quality Requirements
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
            fi
            ;;
        alpine)
            if [ -f /etc/login.defs ]; then
                sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs 2>/dev/null
                sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs 2>/dev/null
            fi
            ;;
        arch)
            if [ -f /etc/login.defs ]; then
                sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs 2>/dev/null
                sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs 2>/dev/null
                sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t14/' /etc/login.defs 2>/dev/null
            fi
            
            install_package "libpwquality"
            ;;
    esac
    
    log "Additional security measures applied"
}

################################################################################
# Automatic Updates
################################################################################

setup_automatic_updates() {
    log_section "Setting Up Automatic Security Updates"
    
    case "$DISTRO_FAMILY" in
        debian)
            install_package "unattended-upgrades" || return 1
            install_package "apt-listchanges" || return 1
            dpkg-reconfigure -plow unattended-upgrades 2>&1 | tee -a "$LOG_FILE" >/dev/null
            ;;
        rhel)
            install_package "dnf-automatic" || install_package "yum-cron" || return 1
            
            if command -v dnf &> /dev/null; then
                # Configure dnf-automatic
                if [ -f /etc/dnf/automatic.conf ]; then
                    sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null
                fi
                service_enable dnf-automatic.timer
                service_start dnf-automatic.timer
            else
                # Configure yum-cron
                if [ -f /etc/yum/yum-cron.conf ]; then
                    sed -i 's/apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf 2>/dev/null
                fi
                service_enable yum-cron
                service_start yum-cron
            fi
            ;;
        alpine)
            log_warning "Automatic updates not configured for Alpine (apk upgrade must be run manually)"
            ;;
        arch)
            log_warning "Automatic updates not recommended for Arch Linux"
            log_warning "Consider using a tool like 'yay' or checking for updates regularly"
            ;;
        suse)
            install_package "yast2-online-update-configuration" || log_warning "Failed to install update configuration"
            ;;
    esac
    
    log "Automatic security updates configured (where applicable)"
}

################################################################################
# Security Report Generation
################################################################################

generate_security_report() {
    log_section "Generating Security Report"
    
    local report_file="/root/security_hardening_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=========================================="
        echo "Security Hardening Report"
        echo "Generated: $(date)"
        echo "=========================================="
        echo ""
        echo "System Information:"
        echo "  Distribution: $DISTRO_PRETTY"
        echo "  Kernel: $(uname -r)"
        echo "  Hostname: $(hostname)"
        echo "  Package Manager: $PKG_MANAGER"
        echo "  Firewall: $FIREWALL_TOOL"
        echo ""
        
        case "$FIREWALL_TOOL" in
            ufw)
                echo "Firewall Status (UFW):"
                ufw status verbose 2>/dev/null || echo "  UFW not configured"
                ;;
            firewalld)
                echo "Firewall Status (firewalld):"
                firewall-cmd --list-all 2>/dev/null || echo "  Firewalld not configured"
                ;;
            iptables)
                echo "Firewall Status (iptables):"
                iptables -L -n 2>/dev/null | head -20 || echo "  Iptables not configured"
                ;;
        esac
        
        echo ""
        echo "SSH Configuration:"
        grep -E "^(PermitRootLogin|PasswordAuthentication)" /etc/ssh/sshd_config 2>/dev/null || echo "  SSH config not found"
        echo ""
        
        if command -v systemctl &> /dev/null; then
            echo "Audit Status:"
            systemctl status auditd --no-pager 2>/dev/null | head -5 || echo "  Auditd not running"
            echo ""
        fi
        
        echo "Listening Services:"
        ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || echo "  Unable to list services"
        echo ""
        echo "=========================================="
        echo "Backup Location: $BACKUP_DIR"
        echo "Log File: $LOG_FILE"
        echo "=========================================="
    } | tee "$report_file" > /dev/null
    
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
                # Note: restore function would need to be implemented
                log_warning "Restore function not yet implemented for universal script"
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
    echo "Universal Linux Security Hardening Script"
    echo "Version 3.0 - Multi-Distribution Support"
    echo "=========================================="
    echo ""
    echo "Detected System: $DISTRO_PRETTY"
    echo "Package Manager: $PKG_MANAGER"
    echo "Firewall: $FIREWALL_TOOL"
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
    secure_boot
    configure_ipv6
    configure_sysctl
    additional_security
    
    # Optional components (skip in minimal mode)
    if [ "$minimal_mode" = false ]; then
        setup_fail2ban
        setup_clamav
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
            reboot
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