#!/bin/bash
###############################################################################
# PenTrix Linux CTF — Setup Script
# Creates users, flags, SUID binaries, cron jobs, and misconfigurations.
# Run during Docker build (not at runtime).
###############################################################################
set -e

echo "[*] PenTrix Linux CTF — Setting up vulnerable environment..."

# ══════════════════════════════════════
# 1. USERS
# ══════════════════════════════════════
# pentester — the player's SSH user (weak password: pentester)
useradd -m -s /bin/bash pentester
echo "pentester:pentester" | chpasswd

# sysadmin — a careless sysadmin account (password in a file the player will find)
useradd -m -s /bin/bash sysadmin
echo "sysadmin:Pr1v3sc_2024!" | chpasswd
usermod -aG sudo sysadmin

# dbadmin — service account with leftover files
useradd -m -s /bin/bash dbadmin
echo "dbadmin:Db4dm1n_N0L0g1n_2024" | chpasswd

# Ensure SSH dir exists
mkdir -p /run/sshd

# Allow password auth for SSH
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Make sure these are uncommented
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config


# ══════════════════════════════════════
# FLAG 1 — Web Recon (Apache landing page source comment)
# ══════════════════════════════════════
# The flag is embedded in /var/www/html/index.html (copied via Dockerfile)
echo "[+] Flag 1: Web Recon — in Apache landing page source"


# ══════════════════════════════════════
# FLAG 2 — Directory Enumeration (hidden directory on web server)
# ══════════════════════════════════════
mkdir -p /var/www/html/.secret-backup
cat > /var/www/html/.secret-backup/credentials.txt <<'CRED'
======================================
 PenTrix Corp — Internal Credentials
======================================
Database: postgres://dbadmin:DbP@ss2024@db:5432/pentrix
Redis:    redis://redis:6379/0
SSH Key Passphrase: TrustNo1!

FLAG 2: flag{directory_enum_hidden_backup}

NOTE: This file should have been removed after migration.
CRED

# Also add a robots.txt hinting at the directory
cat > /var/www/html/robots.txt <<'ROBOT'
User-agent: *
Disallow: /.secret-backup/
Disallow: /server-status
Disallow: /admin/
ROBOT

echo "[+] Flag 2: Directory Enum — in .secret-backup/credentials.txt"


# ══════════════════════════════════════
# FLAG 3 — Weak SSH Credentials (the player SSHs in as pentester)
# ══════════════════════════════════════
# The flag is placed in /home/pentester/flag3.txt, readable only by pentester
cat > /home/pentester/flag3.txt <<'FLAG3'
╔══════════════════════════════════════════════════════╗
║  FLAG 3: flag{weak_ssh_credentials_pentester}        ║
║                                                      ║
║  You logged in with weak credentials.                ║
║  Hint: Look around for privilege escalation paths.   ║
║  Try: find / -perm -4000 2>/dev/null                 ║
║  Try: cat /etc/crontab                               ║
╚══════════════════════════════════════════════════════╝
FLAG3
chown pentester:pentester /home/pentester/flag3.txt
chmod 400 /home/pentester/flag3.txt

echo "[+] Flag 3: Weak SSH — in /home/pentester/flag3.txt"


# ══════════════════════════════════════
# FLAG 4 — File Permission Misconfiguration
# ══════════════════════════════════════
# sysadmin left a world-readable password file
mkdir -p /home/sysadmin/.config
cat > /home/sysadmin/.config/backup_creds.txt <<'CRED4'
# Backup service credentials — DO NOT SHARE
# Last updated: 2024-06-15
sysadmin_password=Pr1v3sc_2024!
db_backup_key=xK9mZ2pQ7wR4
flag=flag{world_readable_sysadmin_creds}
CRED4
chown sysadmin:sysadmin /home/sysadmin/.config/backup_creds.txt
chmod 644 /home/sysadmin/.config/backup_creds.txt  # MISCONFIGURED: world-readable!

# Also leave breadcrumbs for the player
cat > /home/pentester/.bash_history <<'HIST'
ls -la /home/
ls -la /home/sysadmin/
cat /etc/passwd
find / -perm -4000 2>/dev/null
cat /etc/crontab
sudo -l
HIST
chown pentester:pentester /home/pentester/.bash_history

echo "[+] Flag 4: File Permissions — in sysadmin's world-readable backup_creds.txt"


# ══════════════════════════════════════
# FLAG 5 — SUID Binary Exploitation
# ══════════════════════════════════════
# Create a vulnerable SUID binary that reads any file as root
cat > /tmp/readfile.c <<'SUIDC'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * PenTrix Vulnerable File Reader
 * This binary has the SUID bit set — it runs as root.
 * Use it to read files you normally can't access.
 * HINT: /root/flag5.txt
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filepath>\n", argv[0]);
        printf("Reads the contents of any file.\n");
        return 1;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("Cannot open file");
        return 1;
    }
    char buf[4096];
    while (fgets(buf, sizeof(buf), f)) {
        printf("%s", buf);
    }
    fclose(f);
    return 0;
}
SUIDC

gcc -o /usr/local/bin/readfile /tmp/readfile.c
chmod 4755 /usr/local/bin/readfile   # SUID bit set — runs as root!
rm /tmp/readfile.c

# Place the flag where only root can read
mkdir -p /root
cat > /root/flag5.txt <<'FLAG5'
╔══════════════════════════════════════════════════════╗
║  FLAG 5: flag{suid_binary_privesc_readfile}          ║
║                                                      ║
║  You exploited a SUID binary to read root's files.   ║
║  In real pentests, always check:                     ║
║    find / -perm -4000 -type f 2>/dev/null            ║
║  Tools like GTFOBins catalog exploitable binaries.   ║
╚══════════════════════════════════════════════════════╝
FLAG5
chmod 400 /root/flag5.txt

echo "[+] Flag 5: SUID Binary — /usr/local/bin/readfile → /root/flag5.txt"


# ══════════════════════════════════════
# FLAG 6 — Cron Job Exploitation
# ══════════════════════════════════════
# A cron job runs a world-writable script as root every minute
mkdir -p /opt/scripts

cat > /opt/scripts/cleanup.sh <<'CRON6'
#!/bin/bash
# Automated cleanup script — runs every minute as root
# Clear temp files
rm -rf /tmp/cleanup_*
# Log the run
echo "Cleanup ran at $(date)" >> /var/log/cleanup.log
CRON6
chmod 777 /opt/scripts/cleanup.sh  # MISCONFIGURED: world-writable!

# Add the cron job
echo "* * * * * root /opt/scripts/cleanup.sh" > /etc/cron.d/cleanup_job
chmod 644 /etc/cron.d/cleanup_job

# Place the flag where the player needs root (or cron abuse) to discover
cat > /root/flag6.txt <<'FLAG6'
╔══════════════════════════════════════════════════════╗
║  FLAG 6: flag{cron_job_writable_script_privesc}      ║
║                                                      ║
║  You modified a world-writable cron script to get    ║
║  code execution as root!                             ║
║  Steps:                                              ║
║    1. cat /etc/cron.d/cleanup_job                    ║
║    2. echo "cp /root/flag6.txt /tmp/f6" >>           ║
║       /opt/scripts/cleanup.sh                        ║
║    3. Wait 1 minute, then cat /tmp/f6                ║
╚══════════════════════════════════════════════════════╝
FLAG6
chmod 400 /root/flag6.txt

# Also hint in crontab
cat >> /etc/crontab <<'CRONTAB'

# System maintenance
# See /etc/cron.d/ for additional jobs
CRONTAB

echo "[+] Flag 6: Cron Job — writable /opt/scripts/cleanup.sh → /root/flag6.txt"


# ══════════════════════════════════════
# FLAG 7 — Root Flag (sudo via sysadmin)
# ══════════════════════════════════════
# The player must escalate to sysadmin (using creds from Flag 4),
# then use sudo to become root.
cat > /root/flag7.txt <<'FLAG7'
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   FLAG 7: flag{root_access_full_compromise}                      ║
║                                                                  ║
║   ██████╗  ██████╗  ██████╗ ████████╗███████╗██████╗ ██╗        ║
║   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔══██╗██║       ║
║   ██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██║  ██║██║       ║
║   ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██║  ██║╚═╝       ║
║   ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██████╔╝██╗       ║
║   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═════╝ ╚═╝      ║
║                                                                  ║
║   Congratulations! You have full root access.                    ║
║                                                                  ║
║   Attack Path:                                                   ║
║   1. Web Recon → found hidden comment (Flag 1)                   ║
║   2. Directory Enum → .secret-backup (Flag 2)                    ║
║   3. Weak SSH → pentester:pentester (Flag 3)                     ║
║   4. File Permissions → sysadmin creds exposed (Flag 4)          ║
║   5. SUID Binary → read root files (Flag 5)                     ║
║   6. Cron Job → writable script as root (Flag 6)                 ║
║   7. su sysadmin → sudo su → ROOT (Flag 7)                      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
FLAG7
chmod 400 /root/flag7.txt

echo "[+] Flag 7: Root Flag — /root/flag7.txt (requires sudo via sysadmin)"


# ══════════════════════════════════════
# FLAG 8 — Capability Abuse (Python cap_setuid)
# ══════════════════════════════════════
# Python3 has the cap_setuid capability — player can use it to become root
# without sudo. Requires knowing about Linux capabilities.
if command -v setcap &> /dev/null; then
    setcap cap_setuid+ep /usr/bin/python3.11 2>/dev/null || \
    setcap cap_setuid+ep /usr/bin/python3 2>/dev/null || true
fi

cat > /root/flag8.txt <<'FLAG8'
╔══════════════════════════════════════════════════════╗
║  FLAG 8: flag{linux_capabilities_setuid_python}      ║
║                                                      ║
║  You exploited Python's cap_setuid capability!       ║
║                                                      ║
║  Discovery:                                          ║
║    getcap -r / 2>/dev/null                           ║
║  Exploit:                                            ║
║    python3 -c 'import os;os.setuid(0);               ║
║    os.system("/bin/bash")'                           ║
║                                                      ║
║  Linux capabilities are a finer-grained alternative  ║
║  to SUID. Always check with getcap!                  ║
╚══════════════════════════════════════════════════════╝
FLAG8
chmod 400 /root/flag8.txt

echo "[+] Flag 8: Capability Abuse — Python cap_setuid → /root/flag8.txt"


# ══════════════════════════════════════
# FLAG 9 — SSH Key Found in Backup + Password Reuse
# ══════════════════════════════════════
# An SSH private key is left in a world-readable backup directory.
# The key belongs to dbadmin. dbadmin reused the same password
# that protects their key passphrase.

mkdir -p /var/backups/old-keys

# Generate a real SSH key pair for dbadmin
ssh-keygen -t rsa -b 2048 -f /var/backups/old-keys/id_rsa_dbadmin -N "Db4dm1n_N0L0g1n_2024" -q
mkdir -p /home/dbadmin/.ssh
cp /var/backups/old-keys/id_rsa_dbadmin.pub /home/dbadmin/.ssh/authorized_keys
chown -R dbadmin:dbadmin /home/dbadmin/.ssh
chmod 700 /home/dbadmin/.ssh
chmod 600 /home/dbadmin/.ssh/authorized_keys

# Make the backup directory world-readable (misconfiguration!)
chmod -R 755 /var/backups/old-keys

cat > /home/dbadmin/flag9.txt <<'FLAG9'
╔══════════════════════════════════════════════════════╗
║  FLAG 9: flag{ssh_key_backup_password_reuse}         ║
║                                                      ║
║  You found an SSH key in /var/backups/old-keys/ and  ║
║  cracked or reused the passphrase from the creds     ║
║  found in Flag 4!                                    ║
║                                                      ║
║  Attack chain:                                       ║
║    1. Find key: ls -la /var/backups/old-keys/        ║
║    2. Crack passphrase (reuse from backup_creds.txt) ║
║    3. ssh -i id_rsa_dbadmin dbadmin@localhost         ║
║    4. Read this flag!                                 ║
║                                                      ║
║  Lesson: Never reuse passwords across services.      ║
╚══════════════════════════════════════════════════════╝
FLAG9
chown dbadmin:dbadmin /home/dbadmin/flag9.txt
chmod 400 /home/dbadmin/flag9.txt

# Leave a hint in the backup directory
cat > /var/backups/old-keys/README.txt <<'KEYREADME'
# Key Migration Notes
# -------------------
# These keys were used before the migration.
# dbadmin's key passphrase was set to their standard password.
# TODO: Remove this directory after verifying new key deployment.
KEYREADME

echo "[+] Flag 9: SSH Key Backup — /var/backups/old-keys/id_rsa_dbadmin → dbadmin"


# ══════════════════════════════════════
# FLAG 10 — Internal Network Recon (discover web app from CTF box)
# ══════════════════════════════════════
# The Linux CTF machine is on the same Docker network as the web app.
# Player must perform internal network reconnaissance to discover
# the web app and access an internal-only endpoint.

cat > /root/flag10.txt <<'FLAG10'
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   FLAG 10: flag{internal_network_pivot_complete}                 ║
║                                                                  ║
║   ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗                       ║
║   ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝                       ║
║   ██████╔╝██║██║   ██║██║   ██║   ██║                           ║
║   ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║                           ║
║   ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║                           ║
║   ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝                          ║
║                                                                  ║
║   You pivoted from the Linux CTF machine to the internal         ║
║   network and accessed the web application!                      ║
║                                                                  ║
║   Attack Path:                                                   ║
║   1. SSH into Linux CTF (pentester:pentester)                    ║
║   2. Enumerate network: ip a, arp -a, nmap 10.10.1.0/24         ║
║   3. Discover pentrix-web-01 at 10.10.1.10:5000                 ║
║   4. curl http://10.10.1.10:5000/debug                          ║
║   5. Access the internal service at 10.10.2.10 via SSRF         ║
║                                                                  ║
║   This is how real attackers pivot through networks.             ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
FLAG10
chmod 400 /root/flag10.txt

# Create a network recon hint script
cat > /home/pentester/network_scan.sh <<'NETSCAN'
#!/bin/bash
# Quick network scanner — find live hosts on the local subnet
echo "=== PenTrix Network Scanner ==="
echo "Scanning local interfaces..."
ip -4 addr show | grep inet
echo ""
echo "ARP table (known hosts):"
arp -a 2>/dev/null || ip neigh show
echo ""
echo "Hint: Try pinging the gateway and nearby IPs"
echo "      The web application is on the same network..."
NETSCAN
chmod +x /home/pentester/network_scan.sh
chown pentester:pentester /home/pentester/network_scan.sh

# Install nmap for network recon
apt-get update -qq && apt-get install -y -qq nmap > /dev/null 2>&1 || true

# Add network recon breadcrumbs
cat >> /home/pentester/.bash_history <<'HIST2'
ip addr show
cat /etc/hosts
ping -c 1 10.10.1.10
curl http://10.10.1.10:5000/
nmap -sV 10.10.1.0/24
HIST2

echo "[+] Flag 10: Network Pivot — internal recon from CTF box → find web app"


# ══════════════════════════════════════
# ADDITIONAL REALISM — Logs, Mail, Services
# ══════════════════════════════════════

# Add fake auth.log with failed login attempts (breadcrumbs)
mkdir -p /var/log
cat > /var/log/auth.log <<'AUTHLOG'
Mar 15 09:14:22 pentrix-linux-01 sshd[1234]: Failed password for root from 10.10.1.10 port 52341 ssh2
Mar 15 09:14:25 pentrix-linux-01 sshd[1234]: Failed password for root from 10.10.1.10 port 52342 ssh2
Mar 15 09:15:01 pentrix-linux-01 sshd[1235]: Accepted password for pentester from 10.10.1.10 port 52350 ssh2
Mar 15 09:22:45 pentrix-linux-01 sudo: sysadmin : TTY=pts/1 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/bin/bash
Mar 15 09:23:01 pentrix-linux-01 sshd[1240]: Failed password for dbadmin from 10.10.1.10 port 52401 ssh2
Mar 15 10:00:01 pentrix-linux-01 CRON[1250]: (root) CMD (/opt/scripts/cleanup.sh)
Mar 15 10:01:01 pentrix-linux-01 CRON[1251]: (root) CMD (/opt/scripts/cleanup.sh)
AUTHLOG
chmod 644 /var/log/auth.log

# Add fake mail for pentester with hints
mkdir -p /var/mail
cat > /var/mail/pentester <<'MAIL'
From sysadmin@pentrix-linux-01  Fri Mar 15 08:00:00 2024
Subject: Server Maintenance Reminder
To: pentester@pentrix-linux-01

Hey,

Just a reminder that the cleanup script runs every minute as root.
Don't touch /opt/scripts/cleanup.sh unless you absolutely have to.

Also, I left my backup credentials in ~/.config/backup_creds.txt
in case you need to access the backup service while I'm out.

The database team moved their old SSH keys to /var/backups/old-keys/.
They should have deleted them by now but you know how it is...

Also, I noticed Python has some extra capabilities set on it.
Not sure who did that. Run 'getcap' to check if it's a concern.

- sysadmin

From admin@pentrix-corp.internal  Fri Mar 15 09:00:00 2024
Subject: Network Architecture
To: all-staff@pentrix-linux-01

Team,

Our Docker network layout:
  DMZ (10.10.1.0/24): This machine + web portal
  Internal (10.10.2.0/24): API server + Redis

The web portal runs at 10.10.1.10:5000.
The internal API is at 10.10.2.20:8080 (not directly accessible from DMZ).

If you need to reach internal services, route through the web app.

- Admin
MAIL
chmod 644 /var/mail/pentester


# ══════════════════════════════════════
# EXTRA MISCONFIGURATIONS & BREADCRUMBS
# ══════════════════════════════════════

# /etc/passwd is always world-readable (normal), but let's add a comment
# to /etc/issue to welcome players
cat > /etc/issue <<'ISSUE'
═══════════════════════════════════════════════════════
  PenTrix Linux CTF — Vulnerable Training Machine
  10 flags hidden. Can you find them all?
  
  Start with web recon (port 80), then pivot to SSH.
  Check capabilities, backups, and the internal network.
═══════════════════════════════════════════════════════

ISSUE

# Leave a note in dbadmin's home
mkdir -p /home/dbadmin
cat > /home/dbadmin/README.txt <<'DBREADME'
Database Migration Notes
========================
Migration completed 2024-06-10.
Old backup credentials moved to sysadmin's config directory.
TODO: Remove /var/www/html/.secret-backup/ (contains old creds!)
DBREADME
chown dbadmin:dbadmin /home/dbadmin/README.txt
chmod 644 /home/dbadmin/README.txt

# Add some interesting files for enumeration
cat > /opt/scripts/README.md <<'SCRIPTREADME'
# Maintenance Scripts

- cleanup.sh: Runs every minute via cron. Clears temp files.
- NOTE: Do not modify cleanup.sh — it runs as root!
SCRIPTREADME

# Make /var/log/cleanup.log readable
touch /var/log/cleanup.log
chmod 644 /var/log/cleanup.log

# Apache config — enable directory listing on .secret-backup (for realism)
cat > /etc/apache2/conf-available/pentrix.conf <<'APACHECONF'
<Directory /var/www/html/.secret-backup>
    Options +Indexes
    AllowOverride None
    Require all granted
</Directory>
APACHECONF
a2enconf pentrix || true

echo "[*] PenTrix Linux CTF setup complete! 10 flags planted."
echo "    SSH:   pentester / pentester"
echo "    HTTP:  port 80"
echo "    Flags: Web Recon, Dir Enum, Weak SSH, File Perms, SUID, Cron, Root, Capabilities, SSH Key, Network Pivot"
