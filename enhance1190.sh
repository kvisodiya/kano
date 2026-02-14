#!/bin/bash
set +e
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

LOG="/var/log/enhance.log"
exec > >(tee -a "$LOG") 2>&1

echo "Starting enhancement: $(date)"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

# Additional packages
echo "Installing additional packages..."
apt-get update
apt-get install -y \
    libpam-cracklib \
    usbguard \
    apt-listbugs \
    debsecan \
    checksecurity \
    arpwatch \
    acl \
    vlock \
    libpam-pkcs11 \
    aide-common \
    systemd-journal-remote

# Additional kernel hardening
echo "Additional kernel hardening..."
cat >> /etc/sysctl.d/99-hardening.conf << 'EOF'
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0
net.ipv4.tcp_challenge_ack_limit=1000000
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_max_tw_buckets=1440000
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=15
net.ipv4.conf.all.arp_ignore=1
net.ipv4.conf.all.arp_announce=2
net.ipv4.conf.default.arp_ignore=1
net.ipv4.conf.default.arp_announce=2
net.ipv4.icmp_ratelimit=100
net.ipv4.icmp_ratemask=88089
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
kernel.pid_max=65536
kernel.panic=60
kernel.panic_on_oops=60
vm.panic_on_oom=1
vm.dirty_ratio=30
vm.dirty_background_ratio=5
net.unix.max_dgram_qlen=50
kernel.sched_autogroup_enabled=0
kernel.printk=3 3 3 3
EOF
sysctl --system

# More module blacklisting
echo "Additional module blacklisting..."
cat >> /etc/modprobe.d/blacklist-hardening.conf << 'EOF'
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install gfs2 /bin/true
install fat /bin/true
install vfat /bin/true
install msdos /bin/true
install af_802154 /bin/true
install appletalk /bin/true
install atm /bin/true
install ax25 /bin/true
install can /bin/true
install decnet /bin/true
install econet /bin/true
install ipx /bin/true
install netrom /bin/true
install p8022 /bin/true
install p8023 /bin/true
install psnap /bin/true
install rose /bin/true
install x25 /bin/true
install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install udf /bin/true
install pcspkr /bin/true
install snd_pcsp /bin/true
install soundcore /bin/true
install cdrom /bin/true
install sr_mod /bin/true
install floppy /bin/true
install parport /bin/true
install parport_pc /bin/true
install ppdev /bin/true
install mei /bin/true
install mei_me /bin/true
EOF

# Enhanced SSH
echo "Enhanced SSH hardening..."
cat >> /etc/ssh/sshd_config << 'EOF'
RekeyLimit 512M 1h
AuthenticationMethods publickey
DisableForwarding yes
ExposeAuthInfo no
FingerprintHash sha256
EOF

# SSH moduli hardening
echo "Hardening SSH moduli..."
if [[ -f /etc/ssh/moduli ]]; then
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
    mv /etc/ssh/moduli.safe /etc/ssh/moduli
fi

# PAM hardening
echo "Enhanced PAM hardening..."
cat > /etc/security/faillock.conf << 'EOF'
deny=5
unlock_time=1800
fail_interval=900
audit
even_deny_root
root_unlock_time=3600
dir=/var/run/faillock
EOF

# PAM password history
echo "Configuring password history..."
sed -i '/pam_unix.so/s/$/ remember=12/' /etc/pam.d/common-password 2>/dev/null

# PAM access control
cat > /etc/security/access.conf << 'EOF'
+ : root : LOCAL
+ : ALL : LOCAL
- : ALL : ALL
EOF

# Additional audit rules
echo "Additional audit rules..."
cat >> /etc/audit/rules.d/hardening.rules << 'EOF'
-w /var/log/audit/ -k auditlog
-w /etc/audit/ -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
-w /usr/sbin/augenrules -p x -k audittools
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/default/auditd -p wa -k auditconfig
-w /etc/localtime -p wa -k time
-w /etc/timezone -p wa -k time
-w /etc/ld.so.conf -p wa -k libpath
-w /etc/ld.so.conf.d/ -p wa -k libpath
-w /etc/ld.so.preload -p wa -k libpath
-w /var/log/faillog -p wa -k faillog
-w /var/log/lastlog -p wa -k lastlog
-w /var/log/wtmp -p wa -k wtmp
-w /var/log/btmp -p wa -k btmp
-w /etc/selinux/ -p wa -k selinux
-w /usr/share/selinux/ -p wa -k selinux
-w /var/log/tallylog -p wa -k tallylog
-a always,exit -F arch=b64 -S socket -F a0=2 -k network
-a always,exit -F arch=b64 -S socket -F a0=10 -k network
-a always,exit -F arch=b64 -S connect -k network
-a always,exit -F arch=b64 -S accept -k network
-a always,exit -F arch=b64 -S accept4 -k network
-a always,exit -F arch=b64 -S listen -k network
-a always,exit -F arch=b64 -S bind -k network
-a always,exit -F arch=b64 -S sendto -k network
-a always,exit -F arch=b64 -S recvfrom -k network
-a always,exit -F arch=b64 -S memfd_create -k memfd
-a always,exit -F arch=b64 -S userfaultfd -k userfaultfd
-a always,exit -F arch=b64 -S bpf -k bpf
-a always,exit -F arch=b64 -S pivot_root -k pivot
-a always,exit -F arch=b64 -S chroot -k chroot
-a always,exit -F arch=b64 -S mknod -k specialfiles
-a always,exit -F arch=b64 -S mknodat -k specialfiles
EOF

sed -i '/-e 2/d' /etc/audit/rules.d/hardening.rules
echo "-e 2" >> /etc/audit/rules.d/hardening.rules

augenrules --load 2>/dev/null
systemctl restart auditd

# USBGuard
echo "Configuring USBGuard..."
usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null
systemctl enable usbguard 2>/dev/null
systemctl start usbguard 2>/dev/null

# Arpwatch
echo "Configuring arpwatch..."
systemctl enable arpwatch 2>/dev/null
systemctl start arpwatch 2>/dev/null

# Additional file permissions
echo "Additional file permissions..."

# Secure log files
chmod 600 /var/log/auth.log 2>/dev/null
chmod 600 /var/log/syslog 2>/dev/null
chmod 600 /var/log/kern.log 2>/dev/null
chmod 600 /var/log/cron.log 2>/dev/null
chmod 600 /var/log/mail.log 2>/dev/null
chmod 600 /var/log/dpkg.log 2>/dev/null
chmod 600 /var/log/apt/* 2>/dev/null
chmod 700 /var/log/audit 2>/dev/null
chmod 600 /var/log/audit/* 2>/dev/null

# Secure cron
chmod 600 /etc/crontab
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.weekly
chmod 700 /etc/cron.monthly
chmod 700 /var/spool/cron
chmod 700 /var/spool/cron/crontabs 2>/dev/null

# Secure boot
chmod 600 /boot/grub/grub.cfg 2>/dev/null
chmod 600 /boot/grub/grub.conf 2>/dev/null
chmod 700 /boot 2>/dev/null

# Secure SSH
chmod 700 /etc/ssh
chmod 600 /etc/ssh/*
chmod 644 /etc/ssh/*.pub 2>/dev/null

# Secure sudoers
chmod 440 /etc/sudoers
chmod 440 /etc/sudoers.d/* 2>/dev/null

# Secure passwd files
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/passwd /etc/group /etc/shadow /etc/gshadow
chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null

# Secure /etc
chmod 755 /etc
chmod 644 /etc/shells
chmod 644 /etc/profile
chmod 644 /etc/bashrc 2>/dev/null
chmod 644 /etc/bash.bashrc 2>/dev/null
chmod 600 /etc/security/opasswd 2>/dev/null

# Sticky bit on world-writable
chmod +t /tmp
chmod +t /var/tmp

# Remove world-writable permissions
find /etc -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null
find /usr -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null
find /var -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null

# Remove group-writable from critical
chmod g-w /etc/passwd /etc/group /etc/shadow /etc/gshadow 2>/dev/null

# ACL for sensitive dirs
setfacl -m g::--- /root 2>/dev/null
setfacl -m o::--- /root 2>/dev/null

# Secure home permissions
for dir in /home/*; do
    if [[ -d "$dir" ]]; then
        chmod 700 "$dir"
        chown $(basename "$dir"):$(basename "$dir") "$dir" 2>/dev/null
    fi
done

# Remove unneeded SUID/SGID
echo "Removing additional SUID/SGID..."
chmod u-s /usr/bin/wall 2>/dev/null
chmod u-s /usr/bin/write 2>/dev/null
chmod u-s /usr/bin/bsd-write 2>/dev/null
chmod g-s /usr/bin/wall 2>/dev/null
chmod g-s /usr/bin/write 2>/dev/null
chmod g-s /usr/bin/bsd-write 2>/dev/null
chmod g-s /usr/bin/crontab 2>/dev/null
chmod g-s /usr/bin/ssh-agent 2>/dev/null
chmod g-s /usr/bin/expiry 2>/dev/null
chmod g-s /usr/bin/chage 2>/dev/null
chmod u-s /usr/bin/pkexec 2>/dev/null
chmod u-s /usr/bin/at 2>/dev/null
chmod u-s /usr/bin/fusermount 2>/dev/null
chmod u-s /usr/bin/fusermount3 2>/dev/null
chmod u-s /usr/lib/dbus-1.0/dbus-daemon-launch-helper 2>/dev/null

# Restrict at command
echo "Restricting at..."
touch /etc/at.allow
chmod 600 /etc/at.allow
echo "root" > /etc/at.allow

# Additional login.defs
echo "Additional login.defs..."
grep -q "USERNS_ENABLED" /etc/login.defs || echo "USERNS_ENABLED no" >> /etc/login.defs
grep -q "CREATE_HOME" /etc/login.defs || echo "CREATE_HOME yes" >> /etc/login.defs
grep -q "USERGROUPS_ENAB" /etc/login.defs || echo "USERGROUPS_ENAB yes" >> /etc/login.defs

# Disable ICMP timestamp
echo "Disabling ICMP timestamp..."
iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP 2>/dev/null
iptables -A OUTPUT -p icmp --icmp-type timestamp-reply -j DROP 2>/dev/null
ip6tables -A INPUT -p icmpv6 --icmpv6-type 128 -j DROP 2>/dev/null

# Save iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null

# Fail2ban enhancements
echo "Enhancing fail2ban..."
cat >> /etc/fail2ban/jail.local << 'EOF'

[pam-generic]
enabled = true
filter = pam-generic
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[apache-auth]
enabled = false
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3

[nginx-http-auth]
enabled = false
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
EOF

systemctl restart fail2ban

# Disable unnecessary kernel modules at boot
echo "Creating module load restrictions..."
cat > /etc/modprobe.d/disable-uncommon-filesystems.conf << 'EOF'
install cramfs /bin/false
install freevxfs /bin/false
install hfs /bin/false
install hfsplus /bin/false
install jffs2 /bin/false
install squashfs /bin/false
install udf /bin/false
EOF

cat > /etc/modprobe.d/disable-uncommon-network.conf << 'EOF'
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF

# Journald hardening
echo "Hardening journald..."
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/hardening.conf << 'EOF'
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SplitMode=uid
ForwardToSyslog=yes
MaxRetentionSec=1month
MaxFileSec=1week
EOF
systemctl restart systemd-journald

# Restrict compilers more
echo "Further restricting compilers..."
for bin in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/c++ /usr/bin/make /usr/bin/as /usr/bin/ld /usr/bin/objdump /usr/bin/readelf /usr/bin/nm /usr/bin/strip; do
    if [[ -f "$bin" ]]; then
        chmod 750 "$bin"
        chgrp root "$bin"
    fi
done

# Restrict debug tools
echo "Restricting debug tools..."
for bin in /usr/bin/gdb /usr/bin/strace /usr/bin/ltrace /usr/bin/perf /usr/bin/tcpdump; do
    if [[ -f "$bin" ]]; then
        chmod 750 "$bin"
        chgrp root "$bin"
    fi
done

# Additional service hardening
echo "Additional service hardening..."

# Disable cups if present
systemctl disable cups 2>/dev/null
systemctl stop cups 2>/dev/null
systemctl disable cups-browsed 2>/dev/null
systemctl stop cups-browsed 2>/dev/null

# Disable avahi
systemctl disable avahi-daemon 2>/dev/null
systemctl stop avahi-daemon 2>/dev/null

# Disable modem
systemctl disable ModemManager 2>/dev/null
systemctl stop ModemManager 2>/dev/null

# Secure shared memory
echo "Hardening shared memory..."
if ! grep -q "tmpfs /run/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
fi

# Restrict systemd-coredump
echo "Hardening coredump..."
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/hardening.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
ExternalSizeMax=0
EOF

# Restrict kernel log
chmod 640 /var/log/kern.log 2>/dev/null
chmod 640 /var/log/dmesg 2>/dev/null

# Create security report cron
echo "Creating security report..."
cat > /etc/cron.weekly/security-report << 'EOF'
#!/bin/bash
REPORT_FILE="/var/log/security-report-$(date +%Y%m%d).txt"
{
    echo "===== SECURITY REPORT: $(date) ====="
    echo ""
    echo "===== FAILED LOGINS ====="
    grep "Failed" /var/log/auth.log 2>/dev/null | tail -50
    echo ""
    echo "===== SUCCESSFUL LOGINS ====="
    last -30
    echo ""
    echo "===== LISTENING PORTS ====="
    ss -tulnp
    echo ""
    echo "===== FAIL2BAN STATUS ====="
    fail2ban-client status 2>/dev/null
    fail2ban-client status sshd 2>/dev/null
    echo ""
    echo "===== DISK USAGE ====="
    df -h
    echo ""
    echo "===== LARGE FILES ====="
    find / -xdev -type f -size +100M 2>/dev/null
    echo ""
    echo "===== SETUID FILES ====="
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
    echo ""
    echo "===== WORLD WRITABLE ====="
    find / -xdev -type f -perm -0002 2>/dev/null
    echo ""
    echo "===== ORPHAN FILES ====="
    find / -xdev \( -nouser -o -nogroup \) 2>/dev/null
    echo ""
    echo "===== END REPORT ====="
} > "$REPORT_FILE"
chmod 600 "$REPORT_FILE"
EOF
chmod 700 /etc/cron.weekly/security-report

# Network hardening via sysctl
echo "Additional network hardening..."
cat >> /etc/sysctl.d/99-hardening.conf << 'EOF'
net.ipv4.conf.all.bootp_relay=0
net.ipv4.conf.all.proxy_arp=0
net.ipv4.conf.default.proxy_arp=0
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.default.arp_filter=1
EOF
sysctl --system

# Harden nsswitch
echo "Hardening nsswitch..."
if [[ -f /etc/nsswitch.conf ]]; then
    chmod 644 /etc/nsswitch.conf
    chown root:root /etc/nsswitch.conf
fi

# Secure tmp cleanup
echo "Configuring tmp cleanup..."
cat > /etc/tmpfiles.d/security.conf << 'EOF'
D /tmp 1777 root root 1d
D /var/tmp 1777 root root 7d
e /tmp - - - 1d
e /var/tmp - - - 7d
EOF

# Harden resolv.conf permissions
chmod 644 /etc/resolv.conf 2>/dev/null
chown root:root /etc/resolv.conf 2>/dev/null

# Lock critical accounts
echo "Locking additional accounts..."
for user in sync halt shutdown operator; do
    passwd -l "$user" 2>/dev/null
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null
done

# Secure su
echo "Securing su..."
chmod 4750 /bin/su 2>/dev/null
chmod 4750 /usr/bin/su 2>/dev/null
chgrp wheel /bin/su 2>/dev/null
chgrp wheel /usr/bin/su 2>/dev/null

# Create checksec cron
echo "Creating integrity check cron..."
cat > /etc/cron.daily/integrity-check << 'EOF'
#!/bin/bash
LOG="/var/log/integrity-$(date +%Y%m%d).log"
echo "Integrity check: $(date)" > "$LOG"
debsums -s 2>&1 | head -50 >> "$LOG"
chmod 600 "$LOG"
EOF
chmod 700 /etc/cron.daily/integrity-check

# Update AIDE database
echo "Updating AIDE..."
if [[ -f /var/lib/aide/aide.db.new ]]; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi

# Clean orphan packages
echo "Cleaning orphan packages..."
apt-get autoremove --purge -y 2>/dev/null
deborphan | xargs apt-get purge -y 2>/dev/null

# Clean old logs
echo "Cleaning old logs..."
find /var/log -type f -name "*.gz" -mtime +30 -delete 2>/dev/null
find /var/log -type f -name "*.old" -mtime +30 -delete 2>/dev/null
find /var/log -type f -name "*.[0-9]" -mtime +30 -delete 2>/dev/null
journalctl --vacuum-time=14d 2>/dev/null

# Restart services
echo "Restarting services..."
systemctl daemon-reload
systemctl restart sshd
systemctl restart fail2ban
systemctl restart auditd
systemctl restart rsyslog
systemctl restart systemd-journald

# Check services
echo "Checking services..."
for svc in sshd fail2ban auditd rsyslog ufw apparmor; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "$svc: OK"
    else
        echo "$svc: FAILED"
    fi
done

# Final Lynis audit
echo ""
echo "Running Lynis audit..."
echo ""
lynis audit system --no-colors 2>/dev/null | tee /var/log/lynis-enhanced.log

SCORE=$(grep "Hardening index" /var/log/lynis-enhanced.log | grep -oP '\d+' | head -1)

echo ""
echo "============================================"
echo "ENHANCEMENT COMPLETE"
echo "============================================"
echo ""
echo "New Lynis Score: $SCORE"
echo ""
echo "Enhancements applied:"
echo "  - Additional kernel hardening"
echo "  - IPv6 disabled"
echo "  - More modules blacklisted"
echo "  - USBGuard enabled"
echo "  - Arpwatch enabled"
echo "  - SSH moduli hardened"
echo "  - PAM faillock configured"
echo "  - Password history (12)"
echo "  - Additional audit rules"
echo "  - SUID/SGID cleanup"
echo "  - File permissions hardened"
echo "  - Compilers restricted"
echo "  - Debug tools restricted"
echo "  - Journald hardened"
echo "  - Weekly security reports"
echo "  - Daily integrity checks"
echo ""
echo "Log: $LOG"
echo "Lynis: /var/log/lynis-enhanced.log"
echo ""
echo "REBOOT NOW: sudo reboot"
echo "============================================"
