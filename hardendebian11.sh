#!/bin/bash
set +e
export DEBIAN_FRONTEND=noninteractive
TOR_DNS="${1:-no}"

echo "[*] Updating system and installing packages..."
apt update && apt full-upgrade -y
apt install -y lynis fail2ban sysstat auditd audispd-plugins ufw curl wget \
  libpam-pwquality libpam-tmpdir apt-listbugs needrestart debsums \
  apt-show-versions acct rkhunter chkrootkit aide apparmor apparmor-utils \
  libpam-apparmor logrotate rsyslog tcpd psmisc lsof

[[ "$TOR_DNS" == "tor" ]] && apt install -y tor unbound

echo "[*] Kernel hardening..."
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=0
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5
net.ipv4.ip_forward=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
kernel.randomize_va_space=2
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=2
kernel.sysrq=0
kernel.core_uses_pid=1
kernel.dmesg_restrict=1
kernel.perf_event_paranoid=3
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
EOF
sysctl --system

echo "[*] Disabling unused filesystems and protocols..."
cat > /etc/modprobe.d/hardening.conf << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install squashfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install usb-storage /bin/true
install firewire-core /bin/true
install thunderbolt /bin/true
EOF

echo "[*] SSH hardening (ports 22 + 2222)..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat > /etc/ssh/sshd_config << 'EOF'
Port 22
Port 2222
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
LoginGraceTime 30
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 3
MaxSessions 3
MaxStartups 10:30:60
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserEnvironment no
DebianBanner no
Banner /etc/issue.net
Compression no
LogLevel VERBOSE
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO
EOF
rm -f /etc/ssh/ssh_host_*
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" > /etc/ssh/ssh_config.d/hardening.conf

echo "[*] Setting banners..."
cat > /etc/issue << 'EOF'
********************************************************************
*                    AUTHORIZED ACCESS ONLY                        *
*  Unauthorized access is prohibited and will be prosecuted.       *
*  All activities are logged and monitored.                        *
********************************************************************
EOF
cp /etc/issue /etc/issue.net
cat > /etc/motd << 'EOF'
System protected by security monitoring. All actions are logged.
EOF

echo "[*] Umask and session timeout..."
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
cat > /etc/profile.d/hardening.sh << 'EOF'
umask 027
TMOUT=900
readonly TMOUT
export TMOUT
EOF
chmod 644 /etc/profile.d/hardening.sh

echo "[*] Password policy..."
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 3
gecoscheck = 1
dictcheck = 1
enforcing = 1
EOF
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES 3/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT 60/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs

echo "[*] Core dump restrictions..."
echo "* hard core 0" >> /etc/security/limits.conf
echo "* soft core 0" >> /etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
echo -e "[Coredump]\nStorage=none\nProcessSizeMax=0" > /etc/systemd/coredump.conf.d/disable.conf

echo "[*] Configuring UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw limit 22/tcp comment 'SSH rate limit'
ufw limit 2222/tcp comment 'SSH alt rate limit'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw logging high
ufw --force enable

echo "[*] Configuring Fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
banaction = ufw
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = 22,2222
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 86400
findtime = 3600

[sshd-ddos]
enabled = true
port = 22,2222
filter = sshd-ddos
logpath = %(sshd_log)s
maxretry = 6
bantime = 86400

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 604800
findtime = 86400
maxretry = 3
EOF
systemctl enable fail2ban
systemctl restart fail2ban

echo "[*] Configuring Auditd..."
cat > /etc/audit/rules.d/hardening.rules << 'EOF'
-D
-b 8192
-f 1
--backlog_wait_time 60000
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /var/log/auth.log -p wa -k auth_log
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/pam.d/ -p wa -k pam
-w /etc/nsswitch.conf -p wa -k nsswitch
-w /etc/hosts -p wa -k hosts
-w /etc/network/ -p wa -k network
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
-a always,exit -F arch=b64 -S mount -S umount2 -k mount
-a always,exit -F arch=b64 -S unlink -S rmdir -S rename -k delete
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -k owner_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k xattr
-a always,exit -F arch=b64 -S removexattr -S lremovexattr -S fremovexattr -k xattr
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -k access
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /bin/kmod -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S ptrace -k tracing
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs/ -p wa -k cron
-w /etc/localtime -p wa -k time
-w /usr/bin/sudo -p x -k sudo
-w /usr/bin/su -p x -k su
-e 2
EOF
systemctl enable auditd
augenrules --load 2>/dev/null || true
systemctl restart auditd

echo "[*] Process accounting..."
systemctl enable acct
touch /var/log/account/pacct
/usr/sbin/accton on 2>/dev/null || /usr/sbin/accton /var/log/account/pacct

echo "[*] Sysstat..."
sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
systemctl enable sysstat
systemctl restart sysstat

echo "[*] AppArmor..."
systemctl enable apparmor
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

echo "[*] Logging improvements..."
cat > /etc/rsyslog.d/50-hardening.conf << 'EOF'
$FileCreateMode 0640
auth,authpriv.* /var/log/auth.log
*.*;auth,authpriv.none -/var/log/syslog
cron.* /var/log/cron.log
kern.* -/var/log/kern.log
EOF
systemctl restart rsyslog

echo "[*] Secure permissions..."
chmod 700 /root
chmod 600 /etc/crontab
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
chmod 600 /etc/ssh/sshd_config
chmod 640 /etc/shadow /etc/gshadow
chown root:shadow /etc/shadow /etc/gshadow
chmod 644 /etc/passwd /etc/group
find /var/log -type f -exec chmod 640 {} \;

echo "[*] Disable unnecessary services..."
for svc in avahi-daemon cups bluetooth; do
    systemctl disable "$svc" 2>/dev/null
    systemctl stop "$svc" 2>/dev/null
done

echo "[*] Remove unnecessary SUID/SGID..."
for bin in /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp; do
    [[ -f "$bin" ]] && chmod u-s "$bin" 2>/dev/null
done

if [[ "$TOR_DNS" == "tor" ]]; then
    echo "[*] Configuring Tor + Unbound DNS privacy..."
    cat > /etc/unbound/unbound.conf.d/dns-privacy.conf << 'EOF'
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    do-not-query-localhost: no
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    aggressive-nsec: yes
    prefetch: yes
    rrset-roundrobin: yes
    use-caps-for-id: yes
forward-zone:
    name: "."
    forward-addr: 127.0.0.1@9053
EOF
    grep -q "DNSPort 9053" /etc/tor/torrc || echo "DNSPort 9053" >> /etc/tor/torrc
    echo "AutomapHostsOnResolve 1" >> /etc/tor/torrc
    systemctl enable tor unbound
    systemctl restart tor
    sleep 3
    systemctl restart unbound
    chattr -i /etc/resolv.conf 2>/dev/null
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    chattr +i /etc/resolv.conf
    echo "[+] Tor DNS privacy configured."
fi

echo "[*] Initialize AIDE..."
aideinit 2>/dev/null &

echo "[*] Cleanup..."
apt autoremove --purge -y
apt autoclean -y
apt clean
rm -rf /tmp/* /var/tmp/* 2>/dev/null
journalctl --vacuum-time=7d 2>/dev/null

echo "[*] Restarting SSH..."
systemctl restart sshd

echo ""
echo "=============================================="
echo "         RUNNING LYNIS SECURITY AUDIT        "
echo "=============================================="
lynis audit system --no-colors 2>/dev/null | tee /var/log/lynis-audit.log

SCORE=$(grep "Hardening index" /var/log/lynis-audit.log | grep -oP '\d+' | head -1)
echo ""
echo "=============================================="
echo "          HARDENING COMPLETE                 "
echo "=============================================="
echo "Lynis Score: ${SCORE:-Check /var/log/lynis-audit.log}"
echo "SSH Ports: 22 and 2222"
echo "Firewall: UFW enabled (22,2222,80,443 allowed)"
echo "Fail2ban: Active"
echo "Audit: Enabled"
[[ "$TOR_DNS" == "tor" ]] && echo "DNS: Tor+Unbound (privacy mode)"
echo ""
echo ">>> REBOOT RECOMMENDED: sudo reboot <<<"
echo "=============================================="
