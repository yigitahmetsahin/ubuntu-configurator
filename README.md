## Ubuntu Server Setup & Security Hardening

This directory contains `ubuntu_server_setup.sh`, an interactive CLI script to perform initial setup and security hardening on a fresh Ubuntu server.

### What it does
- **Operation modes**: Choose between `initial-setup`, `network-config`, or `firewall-config`
  - **initial-setup**: Security hardening (no firewall changes)
  - **network-config**: Interactive netplan configuration for an interface (DHCP or static)
  - **firewall-config**: Only configure/reset UFW based on selected role (no SSH/netplan changes)
  - **authorized-key**: Add an SSH public key to a user's `~/.ssh/authorized_keys`
- **Updates system packages**: `apt update && apt upgrade`
- **Configures UFW firewall**: Only in `firewall-config` mode. Resets rules, denies incoming and allows outgoing by default, always allows `ssh`, then opens extra ports based on your selected role
- **Hardens SSH**: disables password authentication, restricts root login, reduces auth retries, disables X11 forwarding, and more
- **Optional Fail2Ban**: if chosen, installs and configures Fail2Ban to protect SSH
 - **Optional Authorized Key**: interactively add an SSH public key to a user's `~/.ssh/authorized_keys`

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
curl -fsSL -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \
  "https://raw.githubusercontent.com/yigitahmetsahin/ubuntu-configurator/main/ubuntu_server_setup.sh?t=$(date +%s)" \
  -o "$HOME/ubuntu_server_setup.sh"
sudo chmod +x "$HOME/ubuntu_server_setup.sh"
sudo "$HOME/ubuntu_server_setup.sh"
```

### Interactive flow
You will be prompted for:
- **Operation mode**: `initial-setup`, `network-config`, or `firewall-config`
  - If `initial-setup`:
    - **Install Fail2Ban (y/N)?**
  - If `authorized-key`:
    - Prompts for username and SSH public key, then creates/updates `~/.ssh/authorized_keys` with secure permissions and avoids duplicates.
  - If `network-config`:
    - **Select interface**: choose from missing (not yet in netplan) or existing interfaces
    - **DHCP (y/N)**: use DHCP for IPv4 or configure static
    - **Network type**: choose between public (internet access) or local (CIDR-specific, no default route)
      - If local: specify CIDR range that should use this interface (e.g., `192.168.0.0/16`); the script prevents `0.0.0.0/0`
    - If static: provide `address (CIDR)` and optional `DNS servers`
    - **Optional (Y/n)**: mark interface as optional to skip boot wait
  - If `firewall-config`:
    - **Select setup type**: same roles as above; script resets UFW and applies role ports only
    - For `redis` and `mariadb`, you'll be prompted to optionally enter a source IP/CIDR. If provided, UFW allows only that source to the role's port; if left empty, it allows from anywhere.

### Role-based firewall rules
The script always allows `ssh` and then opens additional ports per role:
- **redis**: `6379/tcp`
- **mariadb**: `3306/tcp`
- **api**: `80/tcp`, `443/tcp`
- **ui-app**: `80/tcp`, `443/tcp`
- **vpn**: `1194/udp` (OpenVPN UDP), `443/tcp` (OpenVPN TCP & web forwarding), `943/tcp` (Admin/Client Web UI)
- **deployinator**: `80/tcp`, `3000/tcp`, `443/tcp`

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

#### Network routing behavior:
- **Public networks**: Interface becomes the default route for internet traffic (metric 100)
  - **DHCP public**: IP address and default routing managed automatically by DHCP
  - **Static public**: Manual IP configuration with default route via specified gateway
- **Local networks**: Interface never advertises a default gateway; only the specified CIDR range is routed through this interface (metric 100)
  - **DHCP local**: IP obtained via DHCP, but DHCP routes are disabled. You can optionally provide a local gateway, otherwise traffic stays on-link.
  - **Static local**: Manual IP configuration; optional gateway only applies to the specified CIDR range, never to the internet.

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


### Documentation policy
- When adding or updating a feature in this folder, update this `README.md` accordingly.
- Document new flags, environment variables, inputs/outputs, and any breaking changes.
- If a new script or tool is introduced, add a short usage example.

