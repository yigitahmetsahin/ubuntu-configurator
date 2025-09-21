#!/bin/bash

# Ubuntu Server Initial Setup and Security Hardening Script
# This script performs initial setup and security hardening for Ubuntu servers
# Run with: sudo ./ubuntu_server_setup.sh

set -euo pipefail  # Exit on error, undefined vars, pipe failures

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use: sudo $0)"
  exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Helpers for firewall rules
declare -a OPENED_PORTS
OPENED_PORTS=()
CURRENT_ALLOW_SOURCE=""

allow_port() {
    local rule="$1"
    local from_src="${CURRENT_ALLOW_SOURCE:-}"
    if [[ -n "$from_src" ]]; then
        local port proto
        if [[ "$rule" == */* ]]; then
            port="${rule%/*}"
            proto="${rule#*/}"
        else
            port="$rule"
            proto=""
        fi
        if [[ -n "$proto" ]]; then
            ufw allow from "$from_src" to any port "$port" proto "$proto"
        else
            ufw allow from "$from_src" to any port "$port"
        fi
        OPENED_PORTS+=("$rule from $from_src")
    else
        ufw allow "$rule"
        OPENED_PORTS+=("$rule")
    fi
}

configure_ufw_for_role() {
    case "$SETUP_TYPE" in
        redis)
            allow_port "6379/tcp"
            ;;
        mariadb)
            allow_port "3306/tcp"
            ;;
        api)
            allow_port "443/tcp"
            ;;
        ui-app)
            allow_port "443/tcp"
            ;;
        vpn)
            allow_port "1194/udp"
            ;;
        deployinator)
            allow_port "443/tcp"
            ;;
    esac
}

# === Network Configuration (Netplan) ===
network_config_flow() {
    log "Network configuration mode selected"

    # Ensure netplan is installed
    if ! command -v netplan >/dev/null 2>&1; then
        log "Netplan not found. Installing netplan.io..."
        apt update -y
        apt install -y netplan.io
    fi

    # List all non-loopback interfaces (filter common virtual types)
    mapfile -t ALL_IFACES < <(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | grep -vE '^(docker|veth|br|virbr|tun|tap|wg|cni|flannel|kube)')
    if [[ ${#ALL_IFACES[@]} -eq 0 ]]; then
        error "No network interfaces found to configure"
        exit 1
    fi

    # Get interfaces already present in netplan (best-effort)
    local -a EXISTING
    EXISTING=()
    if netplan get >/dev/null 2>&1; then
        mapfile -t EXISTING < <(netplan get 2>/dev/null | awk '
            $1=="ethernets:" {in_eth=1; next}
            in_eth && NF==0 {in_eth=0}
            in_eth && $1 ~ /^[a-zA-Z0-9_-]+:/ { gsub(":","",$1); print $1 }')
    fi

    # Compute missing interfaces (present on system but not in netplan)
    local -a MISSING
    MISSING=()
    local found
    for iface in "${ALL_IFACES[@]}"; do
        found=0
        for ex in "${EXISTING[@]:-}"; do
            if [[ "$iface" == "$ex" ]]; then
                found=1
                break
            fi
        done
        if [[ $found -eq 0 ]]; then
            MISSING+=("$iface")
        fi
    done

    local -a CHOICES
    if [[ ${#MISSING[@]} -gt 0 ]]; then
        CHOICES=("${MISSING[@]}")
    else
        warning "All detected interfaces appear to be defined in netplan already."
        echo
        local _reconf
        read -rp "Reconfigure an existing interface (y/N)? " _reconf || true
        if [[ "${_reconf,,}" != "y" && "${_reconf,,}" != "yes" ]]; then
            log "No changes requested. Exiting."
            exit 0
        fi
        if [[ ${#EXISTING[@]} -gt 0 ]]; then
            CHOICES=("${EXISTING[@]}")
        else
            CHOICES=("${ALL_IFACES[@]}")
        fi
    fi

    echo
    echo "Select interface to configure:"
    PS3="Enter choice [1-${#CHOICES[@]}]: "
    local TARGET_IFACE
    select _opt in "${CHOICES[@]}"; do
        if [[ -n "$_opt" ]]; then
            TARGET_IFACE="$_opt"
            break
        else
            echo "Invalid selection. Try again."
        fi
    done

    echo
    local DHCP4="no"
    read -rp "Use DHCP for IPv4 on ${TARGET_IFACE} (y/N)? " _dhcp || true
    if [[ "${_dhcp,,}" == "y" || "${_dhcp,,}" == "yes" ]]; then
        DHCP4="yes"
    fi

    local ADDRESS_CIDR="" GATEWAY4="" DNS_ADDRESSES="" OPTIONAL_YN="yes"
    if [[ "$DHCP4" == "no" ]]; then
        while true; do
            read -rp "Static IPv4 (CIDR, e.g., 192.168.1.50/24): " ADDRESS_CIDR || true
            if [[ "$ADDRESS_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/(3[0-2]|[12]?[0-9])$ ]]; then
                break
            fi
            echo "Invalid CIDR. Try again."
        done
        while true; do
            read -rp "Default gateway IPv4 (e.g., 192.168.1.1): " GATEWAY4 || true
            if [[ "$GATEWAY4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                break
            fi
            echo "Invalid IPv4. Try again."
        done
        local DNS_INPUT=""
        read -rp "DNS servers (comma-separated, e.g., 1.1.1.1,8.8.8.8) [optional]: " DNS_INPUT || true
        if [[ -n "${DNS_INPUT:-}" ]]; then
            DNS_ADDRESSES=$(echo "$DNS_INPUT" | tr -d ' ' | sed 's/,/, /g')
        fi
    fi

    read -rp "Mark interface as optional (skip boot wait) (Y/n)? " _opt_ans || true
    if [[ "${_opt_ans,,}" == "n" || "${_opt_ans,,}" == "no" ]]; then
        OPTIONAL_YN="no"
    fi

    local NETPLAN_FILE="/etc/netplan/60-${TARGET_IFACE}.yaml"
    if [[ -f "$NETPLAN_FILE" ]]; then
        cp "$NETPLAN_FILE" "${NETPLAN_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        log "Backed up existing ${NETPLAN_FILE}"
    fi

    # Write netplan YAML
    {
        echo "network:"
        echo "    version: 2"
        echo "    renderer: networkd"
        echo "    ethernets:"
        echo "        ${TARGET_IFACE}:"
        if [[ "$DHCP4" == "yes" ]]; then
            echo "            dhcp4: true"
        else
            echo "            dhcp4: false"
            echo "            addresses: [${ADDRESS_CIDR}]"
            echo "            routes:"
            echo "            - to: default"
            echo "              via: ${GATEWAY4}"
            if [[ -n "${DNS_ADDRESSES:-}" ]]; then
                echo "            nameservers:"
                echo "                addresses: [${DNS_ADDRESSES}]"
            fi
        fi
        if [[ "$OPTIONAL_YN" == "yes" ]]; then
            echo "            optional: true"
        fi
    } > "$NETPLAN_FILE"

    log "Wrote netplan configuration to ${NETPLAN_FILE}"
    log "Validating netplan configuration..."
    netplan generate
    success "Netplan configuration is syntactically valid."
    log "Applying netplan configuration..."
    netplan apply
    success "Netplan applied."

    echo
    log "Interface status for ${TARGET_IFACE}:"
    ip addr show "$TARGET_IFACE" || true
    networkctl status "$TARGET_IFACE" --no-pager 2>/dev/null | cat || true
}

# === Firewall Configuration (UFW) ===
firewall_config_flow() {
    log "Firewall configuration mode selected"

    # Select setup type (role)
    echo
    echo "Select setup type:"
    local options=(redis mariadb api ui-app vpn deployinator)
    PS3="Enter choice [1-${#options[@]}]: "
    local opt
    select opt in "${options[@]}"; do
        if [[ -n "$opt" ]]; then
            SETUP_TYPE="$opt"
            break
        else
            echo "Invalid selection. Try again."
        fi
    done

    # Ensure UFW is installed
    if ! command -v ufw &> /dev/null; then
        log "Installing UFW..."
        apt install -y ufw
    fi

    # Reset and configure base rules
    OPENED_PORTS=()
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh

    # Allow role-specific ports
    if [[ "$SETUP_TYPE" == "redis" || "$SETUP_TYPE" == "mariadb" ]]; then
        echo
        read -rp "Restrict access to a specific IP/CIDR (leave empty to allow all): " _src || true
        if [[ -n "${_src:-}" ]]; then
            CURRENT_ALLOW_SOURCE="$_src"
        else
            CURRENT_ALLOW_SOURCE=""
        fi
    else
        CURRENT_ALLOW_SOURCE=""
    fi

    configure_ufw_for_role

    # Enable firewall
    ufw --force enable

    success "UFW firewall configured and enabled (firewall-config mode)"

    # Show what we allowed
    if [[ ${#OPENED_PORTS[@]} -gt 0 ]]; then
        log "Additional allowed ports for $SETUP_TYPE: ${OPENED_PORTS[*]}"
    else
        log "No additional ports opened beyond SSH for $SETUP_TYPE"
    fi

    log "UFW Status:"
    ufw status verbose
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "Starting Ubuntu Server Initial Setup and Security Hardening..."

# === Operation Selection ===
echo
echo "Select operation mode:"
op_options=(initial-setup network-config firewall-config)
PS3="Enter choice [1-${#op_options[@]}]: "
select _op in "${op_options[@]}"; do
    if [[ -n "$_op" ]]; then
        OPERATION_MODE="$_op"
        break
    else
        echo "Invalid selection. Try again."
    fi
done

if [[ "$OPERATION_MODE" == "network-config" ]]; then
    network_config_flow
    exit 0
fi

if [[ "$OPERATION_MODE" == "firewall-config" ]]; then
    firewall_config_flow
    exit 0
fi

# === CLI Prompts ===
# Ask whether to install Fail2Ban
echo
INSTALL_FAIL2BAN="no"
read -rp "Install Fail2Ban (y/N)? " _f2b_answer || true
if [[ "${_f2b_answer,,}" == "y" || "${_f2b_answer,,}" == "yes" ]]; then
    INSTALL_FAIL2BAN="yes"
fi

 

# Step 1: Update the system
log "Step 1: Updating system packages..."
apt update -y
apt upgrade -y
success "System packages updated successfully"

 

# Step 3: Harden SSH Configuration
log "Step 2: Hardening SSH configuration..."

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# SSH hardening configurations
SSH_CONFIG="/etc/ssh/sshd_config"

# Function to update SSH config
update_ssh_config() {
    local key="$1"
    local value="$2"
    
    if grep -q "^#*${key}" "$SSH_CONFIG"; then
        sed -i "s|^#*${key}.*|${key} ${value}|" "$SSH_CONFIG"
    else
        echo "${key} ${value}" >> "$SSH_CONFIG"
    fi
}

# Apply SSH hardening settings
update_ssh_config "PermitRootLogin" "prohibit-password"
update_ssh_config "PubkeyAuthentication" "yes"
update_ssh_config "AuthorizedKeysFile" ".ssh/authorized_keys"
update_ssh_config "PasswordAuthentication" "no"
update_ssh_config "ChallengeResponseAuthentication" "no"
update_ssh_config "UsePAM" "no"
update_ssh_config "X11Forwarding" "no"
update_ssh_config "PrintMotd" "no"
update_ssh_config "ClientAliveInterval" "300"
update_ssh_config "ClientAliveCountMax" "2"
update_ssh_config "MaxAuthTries" "3"
update_ssh_config "MaxStartups" "10:30:60"
update_ssh_config "LoginGraceTime" "60"

success "SSH configuration hardened"

# Step 4: Install and configure Fail2Ban (optional)
if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
    log "Step 3: Installing and configuring Fail2Ban..."

    # Install fail2ban
    apt install -y fail2ban

    # Create custom fail2ban configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban hosts for 1 hour (3600 seconds)
bantime = 3600

# A host is banned if it has generated "maxretry" during the last "findtime" seconds
findtime = 600

# Number of failures before a host get banned
maxretry = 3

# Destination email for notifications
destemail = root@localhost

# Sender email
sender = root@localhost

# MTA (mail transfer agent) to use
mta = sendmail

# Default protocol
protocol = tcp

# Specify chain where jumps would need to be added in iptables-* actions
chain = INPUT

# Default action
action = %(action_)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 6
bantime = 3600
findtime = 600
EOF

    # Create additional SSH filter for more comprehensive protection
    cat > /etc/fail2ban/filter.d/sshd-aggressive.conf << 'EOF'
[Definition]
failregex = ^%(__prefix_line)s(?:error: PAM: )?[aA]uthentication (?:failure|error|failed) for .* from <HOST>( via \S+)?\s*$
            ^%(__prefix_line)s(?:error: )?Received disconnect from <HOST>: 3: .*: Auth fail$
            ^%(__prefix_line)s(?:error: )?Connection closed by <HOST> port \d+ \[preauth\]$
            ^%(__prefix_line)s(?:error: )?PAM: Authentication failure for .* from <HOST>\s*$
            ^%(__prefix_line)s(?:error: )?PAM: User not known to the underlying authentication module for .* from <HOST>\s*$
            ^%(__prefix_line)s(?:error: )?maximum authentication attempts exceeded for .* from <HOST>.*ssh2$
            ^%(__prefix_line)s(?:error: )?User .* from <HOST> not allowed because not listed in AllowUsers$
            ^%(__prefix_line)s(?:error: )?authentication failure; logname=\S* uid=\S* euid=\S* tty=\S* ruser=\S* rhost=<HOST>(?:\s+user=.*)?\s*$
            ^%(__prefix_line)s(?:error: )?refused connect from \S+ \(<HOST>\)$
            ^%(__prefix_line)s(?:error: )?Invalid user .* from <HOST>\s*$
            ^%(__prefix_line)s(?:error: )?User .* from <HOST> not allowed because account is locked$
            ^%(__prefix_line)s(?:error: )?Disconnecting: Too many authentication failures for .* \[preauth\]$

ignoreregex =
EOF

    # Enable and start fail2ban
    systemctl enable fail2ban
    systemctl start fail2ban

    success "Fail2Ban installed, configured, and started"
else
    log "Step 4: Skipping Fail2Ban installation per user choice"
fi

# Step 5: Restart SSH service
log "Step 4: Restarting SSH service to apply changes..."
systemctl restart ssh
success "SSH service restarted"

# Step 5: Display final status
log "Setup completed successfully!"
echo
success "=== SECURITY SETUP SUMMARY ==="
echo "[OK] System packages updated"
if [[ "$OPERATION_MODE" == "firewall-config" ]]; then
echo "[OK] UFW firewall enabled (SSH allowed, all other incoming denied)"
if [[ ${#OPENED_PORTS[@]} -gt 0 ]]; then
echo "[OK] Additional allowed ports for $SETUP_TYPE: ${OPENED_PORTS[*]}"
else
echo "[OK] No additional ports opened beyond SSH"
fi
else
echo "[INFO] Firewall not modified in initial-setup mode"
fi
echo "[OK] SSH hardened (pubkey auth only, PAM disabled, root prohibit-password)"
if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
echo "[OK] Fail2Ban installed and configured for SSH protection"
else
echo "[SKIP] Fail2Ban not installed"
fi
echo

warning "=== IMPORTANT NOTES ==="
echo "1. SSH configuration backup saved to: /etc/ssh/sshd_config.backup.*"
echo "2. Ensure you have SSH key-based access configured before logging out!"
echo "3. Root login is set to 'prohibit-password' - only key-based auth allowed"
echo "4. Password authentication is disabled for all users"
if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
echo "5. Fail2Ban is monitoring SSH attempts with 3 max retries in 10 minutes"
fi
echo

log "Checking service status..."
echo "UFW Status:"
ufw status
echo
if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
echo "Fail2Ban Status:"
systemctl status fail2ban --no-pager -l
fi
echo
echo "SSH Configuration Test:"
sshd -t && success "SSH configuration is valid" || error "SSH configuration has errors"

log "Setup script completed. Please test SSH access before closing this session!"
