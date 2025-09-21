## Ubuntu Server Setup & Security Hardening

This directory contains `ubuntu_server_setup.sh`, an interactive CLI script to perform initial setup and security hardening on a fresh Ubuntu server.

### What it does
- **Operation modes**: Choose between `initial-setup` or `network-config`
  - **initial-setup**: Security hardening and role-based firewall
  - **network-config**: Interactive netplan configuration for an interface (DHCP or static)
- **Updates system packages**: `apt update && apt upgrade`
- **Configures UFW firewall**: resets rules, denies incoming and allows outgoing by default, always allows `ssh`, then opens extra ports based on your selected role
- **Hardens SSH**: disables password authentication, restricts root login, reduces auth retries, disables X11 forwarding, and more
- **Optional Fail2Ban**: if chosen, installs and configures Fail2Ban to protect SSH

### Requirements
- Ubuntu Server with internet access
- Root privileges (run with `sudo`)
- `git` installed (for repo-based install)

### Quick start (GitHub repository)
Recommended: clone the repository on the server and run the script from there.

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/yigitahmetsahin/ubuntu-configurator.git
cd ubuntu-configurator/templates
sudo chmod +x ubuntu_server_setup.sh
sudo ./ubuntu_server_setup.sh
```

Alternatively, download only the script directly from GitHub and run it:

```bash
curl -fsSL https://raw.githubusercontent.com/yigitahmetsahin/ubuntu-configurator/main/ubuntu_server_setup.sh -o ubuntu_server_setup.sh
sudo chmod +x ubuntu_server_setup.sh
sudo ./ubuntu_server_setup.sh
```

### Interactive flow
You will be prompted for:
- **Operation mode**: `initial-setup` or `network-config`
  - If `initial-setup`:
    - **Install Fail2Ban (y/N)?**
    - **Select setup type**: one of `redis`, `mariadb`, `api`, `ui-app`, `vpn`, `deployinator`
  - If `network-config`:
    - **Select interface**: choose from missing (not yet in netplan) or existing interfaces
    - **DHCP (y/N)**: use DHCP for IPv4 or configure static
    - If static: provide `address (CIDR)`, `gateway4`, optional `DNS servers`
    - **Optional (Y/n)**: mark interface as optional to skip boot wait

### Role-based firewall rules
The script always allows `ssh` and then opens additional ports per role:
- **redis**: `6379/tcp`
- **mariadb**: `3306/tcp`
- **api**: `80/tcp`, `443/tcp`
- **ui-app**: `80/tcp`, `443/tcp`
- **vpn**: `1194/udp` (OpenVPN)
- **deployinator**: no additional ports beyond SSH

Notes:
- UFW is reset each run. Re-running the script will re-apply base rules and your selected role.
- SSH hardening is applied unconditionally. Ensure you have working SSH key-based access before running.

### Outputs & verification
The script prints a summary at the end and shows:
- `ufw status` (firewall state)
- `systemctl status fail2ban` (only if installed)
- `sshd -t` (validates SSH config)

When running `network-config`, it also:
- Writes `/etc/netplan/60-<iface>.yaml` (backs up existing file if present)
- Validates configuration (`netplan generate`) and applies it (`netplan apply`)
- Shows interface status: `ip addr show <iface>` and `networkctl status <iface>`

### Troubleshooting
- Check firewall: `sudo ufw status verbose`
- Validate SSH config: `sudo sshd -t`
- Check Fail2Ban (if installed): `sudo systemctl status fail2ban --no-pager -l`
 - Netplan preview: `sudo netplan get`
 - Netplan try (safe apply with rollback): `sudo netplan try`
 - Network logs: `journalctl -u systemd-networkd --no-pager -b`

### Reverting changes (if needed)
- Disable firewall temporarily: `sudo ufw disable`
- Remove Fail2Ban: `sudo apt remove -y fail2ban`
- Restore SSH config backup (created by the script):
```bash
sudo cp /etc/ssh/sshd_config.backup.YYYYMMDD_HHMMSS /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### License
Internal use. Add a license here if required for your project.


