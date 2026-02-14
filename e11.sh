#!/bin/bash
set +e
export DEBIAN_FRONTEND=noninteractive

echo "[*] Lynis 90+ Enhancement Script"

echo "[*] Additional packages..."
apt update
apt install -y libpam-cracklib apt-listchanges debsecan checksecurity \
  usbguard haveged chrony unattended-upgrades

echo "[*] Additional kernel hardening..."
cat >> /etc/sysctl.d/99-hardening.conf << 'EOF'
kernel.modules_disabled=1
kernel.kexec_load_disabled=1
vm.mmap_min_addr=65536
vm.swappiness=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.default.drop_gratuitous_arp=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
kernel.unprivileged_userns_clone=0
dev.tty.ldisc_autoload=0
vm.unprivileged_userfaultfd=0
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0
EOF
sysctl --system

echo "[*] Restrict su to wheel group..."
groupadd -f wheel
sed -i 's/^#\s*auth\s*required\s*pam_wheel.so$/auth required pam_wheel.so use_uid group=wheel/' /etc/pam.d/su
echo "auth required pam_wheel.so use_uid group=wheel" >> /etc/pam.d/su 2>/dev/null

echo "[*] PAM hardening..."
cat > /etc/security/access.conf << 'EOF'
+ : root : LOCAL
+ : ALL : LOCAL
- : ALL : ALL
EOF

cat >> /etc/pam.d/common-auth << 'EOF'
auth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail
EOF

cat >> /etc/pam.d/common-account << 'EOF'
account required pam_tally2.so
EOF

echo "[*] Restrict compiler access..."
for compiler in /usr/bin/gcc* /usr/bin/g++* /usr/bin/cc /usr/bin/c++ /usr/bin/make /usr/bin/as; do
    [[ -f "$compiler" ]] && chmod 700 "$compiler" 2>/dev/null
done

echo "[*] Secure mount options..."
cat > /etc/systemd/system/tmp.mount << 'EOF'
[Unit]
Description=Temporary Directory /tmp
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nodev,nosuid,size=512M

[Install]
WantedBy=local-fs.target
EOF
systemctl daemon-reload
systemctl enable tmp.mount

echo "[*] Secure /dev/shm..."
grep -q "/dev/shm" /etc/fstab || echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab

echo "[*] Secure /proc..."
grep -q "hidepid" /etc/fstab || echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab

echo "[*] Cron restrictions..."
rm -f /etc/cron.deny /etc/at.deny
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow

echo "[*] Harden login.defs..."
cat >> /etc/login.defs << 'EOF'
FAILLOG_ENAB yes
LOG_UNKFAIL_ENAB yes
LOG_OK_LOGINS yes
SYSLOG_SU_ENAB yes
SYSLOG_SG_ENAB yes
SULOG_FILE /var/log/sulog
SU_NAME su
CHFN_RESTRICT rwh
DEFAULT_HOME no
ENV_SUPATH PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH PATH=/usr/local/bin:/usr/bin:/bin
USERGROUPS_ENAB yes
CREATE_HOME yes
EOF

echo "[*] Configure NTP (Chrony)..."
systemctl disable systemd-timesyncd 2>/dev/null
cat > /etc/chrony/chrony.conf << 'EOF'
pool 2.debian.pool.ntp.org iburst maxsources 4
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
leapsectz right/UTC
EOF
systemctl enable chrony
systemctl restart chrony

echo "[*] Automatic security updates..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

echo "[*] USB restrictions (USBGuard)..."
usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true
systemctl enable usbguard 2>/dev/null || true

echo "[*] Additional audit rules..."
cat >> /etc/audit/rules.d/hardening.rules << 'EOF'
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b64 -S accept -S listen -k network_listen
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login
-w /etc/issue -p wa -k banners
-w /etc/issue.net -p wa -k banners
-w /etc/hosts.allow -p wa -k tcpwrappers
-w /etc/hosts.deny -p wa -k tcpwrappers
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/modprobe.d/ -p wa -k modprobe
-w /etc/profile -p wa -k profile
-w /etc/profile.d/ -p wa -k profile
-w /etc/shells -p wa -k shells
-w /etc/security/ -p wa -k security
-w /etc/ld.so.conf -p wa -k libpath
-w /etc/ld.so.conf.d/ -p wa -k libpath
EOF
augenrules --load 2>/dev/null

echo "[*] Stricter SSH..."
cat >> /etc/ssh/sshd_config << 'EOF'
RekeyLimit 512M 1h
AuthenticationMethods publickey
HostbasedAuthentication no
IgnoreRhosts yes
GatewayPorts no
PermitUserRC no
EOF

echo "[*] Legal banners (Lynis compliant)..."
cat > /etc/issue << 'EOF'
#############################################################
#                   AUTHORIZED ACCESS ONLY                   #
#############################################################
# This system is for authorized users only. All activities  #
# are monitored and logged. Unauthorized access attempts    #
# will be reported to law enforcement authorities.          #
# By accessing this system, you consent to monitoring.      #
#############################################################
EOF
cp /etc/issue /etc/issue.net

echo "[*] Shell timeout hardening..."
cat > /etc/profile.d/tmout.sh << 'EOF'
readonly TMOUT=600
export TMOUT
readonly HISTFILE
EOF
chmod 644 /etc/profile.d/tmout.sh

echo "[*] Secure home directories..."
for dir in /home/*; do
    [[ -d "$dir" ]] && chmod 700 "$dir"
done

echo "[*] Remove unnecessary accounts..."
for user in games gnats irc list news uucp; do
    userdel -r "$user" 2>/dev/null
done

echo "[*] Lock system accounts..."
for user in daemon bin sys sync man lp mail proxy backup www-data nobody; do
    passwd -l "$user" 2>/dev/null
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null
done

echo "[*] File permission fixes..."
chmod 600 /etc/crontab
chmod 600 /boot/grub/grub.cfg 2>/dev/null
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
chmod 600 /etc/ssh/sshd_config
chmod 600 /var/log/btmp /var/log/wtmp 2>/dev/null
chown root:utmp /var/log/btmp /var/log/wtmp 2>/dev/null

echo "[*] Disable unused network protocols..."
cat >> /etc/modprobe.d/hardening.conf << 'EOF'
install bluetooth /bin/true
install bnep /bin/true
install btusb /bin/true
install can /bin/true
install atm /bin/true
install ieee1394 /bin/true
install vivid /bin/true
EOF

echo "[*] Configure TCP wrappers..."
echo "ALL: ALL" > /etc/hosts.deny
cat > /etc/hosts.allow << 'EOF'
sshd: ALL
ALL: 127.0.0.1
EOF

echo "[*] Entropy with haveged..."
systemctl enable haveged
systemctl start haveged

echo "[*] AIDE database update..."
aide --config=/etc/aide/aide.conf --init 2>/dev/null &

echo "[*] Cleanup..."
apt autoremove --purge -y
apt autoclean

echo "[*] Restart services..."
systemctl restart sshd
systemctl restart auditd
systemctl restart fail2ban

echo ""
echo "=============================================="
echo "       RUNNING LYNIS VERIFICATION AUDIT      "
echo "=============================================="
lynis audit system --no-colors 2>/dev/null | tee /var/log/lynis-enhanced.log

SCORE=$(grep "Hardening index" /var/log/lynis-enhanced.log | grep -oP '\d+' | head -1)
echo ""
echo "=============================================="
echo "        ENHANCEMENT COMPLETE                 "
echo "=============================================="
echo "New Lynis Score: ${SCORE:-Check /var/log/lynis-enhanced.log}"
echo ""
echo "Additional hardening applied:"
echo "  - Kernel module loading disabled"
echo "  - USBGuard configured"
echo "  - /tmp mounted noexec,nosuid,nodev"
echo "  - /proc hidepid=2"
echo "  - Compiler access restricted"
echo "  - Cron/at access restricted"
echo "  - TCP wrappers configured"
echo "  - Chrony NTP hardened"
echo "  - Automatic security updates enabled"
echo "  - Enhanced PAM/audit rules"
echo "  - Unused accounts removed/locked"
echo ""
echo ">>> REBOOT REQUIRED: sudo reboot <<<"
echo "=============================================="
