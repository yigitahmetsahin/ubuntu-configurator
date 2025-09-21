## Ubuntu Server Setup & Security Hardening

This directory contains `ubuntu_server_setup.sh`, an interactive CLI script to perform initial setup and security hardening on a fresh Ubuntu server.

### What it does
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
curl -fsSL https://raw.githubusercontent.com/yigitahmetsahin/ubuntu-configurator/main/templates/ubuntu_server_setup.sh -o ubuntu_server_setup.sh
sudo chmod +x ubuntu_server_setup.sh
sudo ./ubuntu_server_setup.sh
```

### Interactive flow
You will be prompted for:
- **Install Fail2Ban (y/N)?**: Choose whether to install and enable Fail2Ban
- **Select setup type**: One of `redis`, `mariadb`, `api`, `ui-app`, `vpn`, `deployinator`

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

### Troubleshooting
- Check firewall: `sudo ufw status verbose`
- Validate SSH config: `sudo sshd -t`
- Check Fail2Ban (if installed): `sudo systemctl status fail2ban --no-pager -l`

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


