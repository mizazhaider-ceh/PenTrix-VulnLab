#!/bin/bash
# PenTrix Linux CTF — Entrypoint
# Starts Apache + SSH + Cron, then tails logs to keep container alive

# Start cron daemon
service cron start

# Start SSH daemon
/usr/sbin/sshd

# Start Apache in foreground (keeps container alive)
apachectl -D FOREGROUND
