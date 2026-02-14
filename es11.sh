#!/bin/bash
# security-stack.sh - Production security monitoring
set +e

echo "[*] Installing security stack..."
apt update
apt install -y prometheus-node-exporter logwatch ossec-hids-server \
  suricata crowdsec snoopy 2>/dev/null || apt install -y logwatch snoopy

echo "[*] Snoopy (command logging)..."
echo "/lib/libsnoopy.so" >> /etc/ld.so.preload

echo "[*] Logwatch daily reports..."
cat > /etc/logwatch/conf/logwatch.conf << 'EOF'
MailTo = root
MailFrom = Logwatch
Detail = High
Service = All
Range = yesterday
Format = html
EOF

echo "[*] Daily security report cron..."
cat > /etc/cron.daily/security-report << 'EOF'
#!/bin/bash
{
echo "=== FAILED LOGINS ==="
grep "Failed" /var/log/auth.log | tail -20
echo ""
echo "=== SUCCESSFUL LOGINS ==="
last -20
echo ""
echo "=== LISTENING PORTS ==="
ss -tulnp
echo ""
echo "=== DISK USAGE ==="
df -h
echo ""
echo "=== TOP PROCESSES ==="
ps aux --sort=-%mem | head -10
echo ""
echo "=== FAIL2BAN STATUS ==="
fail2ban-client status
echo ""
echo "=== RECENT AUDIT ALERTS ==="
ausearch -ts recent 2>/dev/null | tail -30
echo ""
echo "=== RKHUNTER CHECK ==="
rkhunter --check --skip-keypress --quiet 2>/dev/null
} | mail -s "Daily Security Report - $(hostname)" root
EOF
chmod +x /etc/cron.daily/security-report

echo "[*] File integrity monitoring cron..."
cat > /etc/cron.weekly/aide-check << 'EOF'
#!/bin/bash
aide --check 2>/dev/null | mail -s "AIDE Integrity Report - $(hostname)" root
EOF
chmod +x /etc/cron.weekly/aide-check

echo "[*] Real-time alerts..."
cat > /usr/local/bin/security-alert << 'EOF'
#!/bin/bash
MSG="$1"
logger -p auth.alert "SECURITY ALERT: $MSG"
echo "$MSG" | wall
EOF
chmod +x /usr/local/bin/security-alert

echo "[+] Security stack installed!"
