################################################################################
# PenTrix Linux CTF — Vulnerable Debian Container
# 7 flags, misconfigurations, SUID binaries, cron jobs, SSH & Apache
# For learning Linux privilege escalation & enumeration
################################################################################
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

# ── Install packages ──
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    openssh-server \
    sudo \
    cron \
    curl \
    vim-tiny \
    nano \
    less \
    procps \
    net-tools \
    iputils-ping \
    file \
    gcc \
    libc6-dev \
    python3 \
    passwd \
    findutils \
    libcap2-bin \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# ── Copy setup assets ──
COPY setup.sh /opt/setup.sh
COPY web/ /var/www/html/
COPY motd /etc/motd

RUN chmod +x /opt/setup.sh && /opt/setup.sh

# ── Expose Apache & SSH ──
EXPOSE 80 22

# ── Entrypoint: start services ──
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
