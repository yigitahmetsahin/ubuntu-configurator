#!/bin/bash

# Ubuntu Server Initial Setup and Security Hardening Script
# This script performs initial setup and security hardening for Ubuntu servers
# Run with: sudo ./ubuntu_server_setup.sh

set -euo pipefail  # Exit on error, undefined vars, pipe failures

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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "Starting Ubuntu Server Initial Setup and Security Hardening..."

# Step 1: Update the system
log "Step 1: Updating system packages..."
apt update -y
apt upgrade -y
success "System packages updated successfully"

# Step 2: Configure UFW Firewall
log "Step 2: Configuring UFW firewall..."

# Install ufw if not already installed
if ! command -v ufw &> /dev/null; then
    log "Installing UFW..."
    apt install -y ufw
fi

# Reset UFW to defaults
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (port 22)
ufw allow ssh
# Alternative: ufw allow 22/tcp

# Enable UFW
ufw --force enable

success "UFW firewall configured and enabled"
log "UFW Status:"
ufw status verbose

# Step 3: Harden SSH Configuration
log "Step 3: Hardening SSH configuration..."

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# SSH hardening configurations
SSH_CONFIG="/etc/ssh/sshd_config"

# Function to update SSH config
update_ssh_config() {
    local key="$1"
    local value="$2"
    
    if grep -q "^#*${key}" "$SSH_CONFIG"; then
        sed -i "s/^#*${key}.*/${key} ${value}/" "$SSH_CONFIG"
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

# Step 4: Install and configure Fail2Ban
log "Step 4: Installing and configuring Fail2Ban..."

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

# Step 5: Restart SSH service
log "Step 5: Restarting SSH service to apply changes..."
systemctl restart sshd
success "SSH service restarted"

# Step 6: Display final status
log "Setup completed successfully!"
echo
success "=== SECURITY SETUP SUMMARY ==="
echo "✓ System packages updated"
echo "✓ UFW firewall enabled (SSH allowed, all other incoming denied)"
echo "✓ SSH hardened (pubkey auth only, PAM disabled, root prohibit-password)"
echo "✓ Fail2Ban installed and configured for SSH protection"
echo

warning "=== IMPORTANT NOTES ==="
echo "1. SSH configuration backup saved to: /etc/ssh/sshd_config.backup.*"
echo "2. Ensure you have SSH key-based access configured before logging out!"
echo "3. Root login is set to 'prohibit-password' - only key-based auth allowed"
echo "4. Password authentication is disabled for all users"
echo "5. Fail2Ban is monitoring SSH attempts with 3 max retries in 10 minutes"
echo

log "Checking service status..."
echo "UFW Status:"
ufw status
echo
echo "Fail2Ban Status:"
systemctl status fail2ban --no-pager -l
echo
echo "SSH Configuration Test:"
sshd -t && success "SSH configuration is valid" || error "SSH configuration has errors"

log "Setup script completed. Please test SSH access before closing this session!"
