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
# EXTRA MISCONFIGURATIONS & BREADCRUMBS
# ══════════════════════════════════════

# /etc/passwd is always world-readable (normal), but let's add a comment
# to /etc/issue to welcome players
cat > /etc/issue <<'ISSUE'
═══════════════════════════════════════════════════════
  PenTrix Linux CTF — Vulnerable Training Machine
  7 flags hidden. Can you find them all?
  
  Start with web recon (port 80), then pivot to SSH.
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

echo "[*] PenTrix Linux CTF setup complete! 7 flags planted."
echo "    SSH:   pentester / pentester"
echo "    HTTP:  port 80"
