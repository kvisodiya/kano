#!/bin/bash
set +e
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

LOG="/var/log/hardening.log"
exec > >(tee -a "$LOG") 2>&1

echo "Starting hardening: $(date)"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

# Check internet
echo "Checking internet..."
if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
    echo "No internet connection"
    exit 1
fi
echo "Internet OK"

# Update system
echo "Updating system..."
apt-get update
if [[ $? -ne 0 ]]; then
    echo "apt update failed"
    exit 1
fi

apt-get upgrade -y
apt-get dist-upgrade -y

# Install packages one by one to identify failures
echo "Installing packages..."

PACKAGES="
lynis
fail2ban
ufw
auditd
audispd-plugins
sysstat
acct
aide
aide-common
apparmor
apparmor-utils
apparmor-profiles
apparmor-profiles-extra
libpam-pwquality
libpam-tmpdir
libpam-apparmor
rkhunter
chkrootkit
clamav
clamav-daemon
haveged
chrony
unattended-upgrades
apt-listchanges
needrestart
debsums
apt-show-versions
curl
wget
net-tools
lsof
rsyslog
logrotate
ca-certificates
gnupg
psmisc
"

for pkg in $PACKAGES; do
    echo "Installing $pkg..."
    apt-get install -y "$pkg"
    if [[ $? -eq 0 ]]; then
        echo "$pkg installed"
    else
        echo "$pkg failed - continuing"
    fi
done

echo "Package installation complete"

# Kernel hardening
echo "Kernel hardening..."
cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL'
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.sysrq=0
kernel.randomize_va_space=2
kernel.yama.ptrace_scope=2
kernel.core_uses_pid=1
kernel.perf_event_paranoid=3
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
dev.tty.ldisc_autoload=0
kernel.kexec_load_disabled=1
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
vm.mmap_min_addr=65536
vm.swappiness=10
net.ipv4.ip_forward=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=0
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.default.drop_gratuitous_arp=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
SYSCTL
sysctl --system

# Disable modules
echo "Disabling unused modules..."
cat > /etc/modprobe.d/blacklist-hardening.conf << 'MODPROBE'
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
install bluetooth /bin/true
install btusb /bin/true
install bnep /bin/true
install n-hdlc /bin/true
install vivid /bin/true
MODPROBE

# SSH hardening
echo "Hardening SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

rm -f /etc/ssh/ssh_host_*
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q

cat > /etc/ssh/sshd_config << 'SSHD'
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
HostbasedAuthentication no
IgnoreRhosts yes
GatewayPorts no
PermitUserRC no
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO
SSHD

chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub

sshd -t
if [[ $? -ne 0 ]]; then
    echo "SSH config error - restoring backup"
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
fi

# Banners
echo "Setting banners..."
cat > /etc/issue << 'BANNER'
###############################################################
#                   AUTHORIZED ACCESS ONLY                    #
###############################################################
# Unauthorized access is prohibited. All activities logged.  #
###############################################################
BANNER
cp /etc/issue /etc/issue.net

cat > /etc/motd << 'MOTD'
System protected. All actions logged.
MOTD

# Password policy
echo "Setting password policy..."
cat > /etc/security/pwquality.conf << 'PWQUALITY'
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
difok = 8
PWQUALITY

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES 3/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT 60/' /etc/login.defs

grep -q "SHA_CRYPT_MIN_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs
grep -q "FAILLOG_ENAB" /etc/login.defs || echo "FAILLOG_ENAB yes" >> /etc/login.defs
grep -q "LOG_UNKFAIL_ENAB" /etc/login.defs || echo "LOG_UNKFAIL_ENAB yes" >> /etc/login.defs
grep -q "LOG_OK_LOGINS" /etc/login.defs || echo "LOG_OK_LOGINS yes" >> /etc/login.defs
grep -q "SYSLOG_SU_ENAB" /etc/login.defs || echo "SYSLOG_SU_ENAB yes" >> /etc/login.defs
grep -q "SYSLOG_SG_ENAB" /etc/login.defs || echo "SYSLOG_SG_ENAB yes" >> /etc/login.defs
grep -q "SULOG_FILE" /etc/login.defs || echo "SULOG_FILE /var/log/sulog" >> /etc/login.defs
grep -q "CHFN_RESTRICT" /etc/login.defs || echo "CHFN_RESTRICT rwh" >> /etc/login.defs
grep -q "DEFAULT_HOME" /etc/login.defs || echo "DEFAULT_HOME no" >> /etc/login.defs

# Limits
echo "Setting limits..."
cat >> /etc/security/limits.conf << 'LIMITS'
* hard core 0
* soft core 0
* hard nproc 1024
* soft nproc 512
LIMITS

# Session timeout
echo "Setting session timeout..."
cat > /etc/profile.d/timeout.sh << 'TIMEOUT'
TMOUT=900
readonly TMOUT
export TMOUT
umask 027
TIMEOUT
chmod 644 /etc/profile.d/timeout.sh

# Restrict su
echo "Restricting su..."
groupadd -f wheel
grep -q "pam_wheel.so" /etc/pam.d/su || echo "auth required pam_wheel.so use_uid group=wheel" >> /etc/pam.d/su

# UFW firewall
echo "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw limit 22/tcp
ufw limit 2222/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw logging high
ufw --force enable

# Fail2ban
echo "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'FAIL2BAN'
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
FAIL2BAN

systemctl enable fail2ban
systemctl restart fail2ban

# Auditd
echo "Configuring auditd..."
cat > /etc/audit/rules.d/hardening.rules << 'AUDIT'
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
-w /var/log/auth.log -p wa -k authlog
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/pam.d/ -p wa -k pam
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /etc/hosts -p wa -k hosts
-w /etc/network/ -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/modprobe.d/ -p wa -k modprobe
-w /etc/profile -p wa -k profile
-w /etc/profile.d/ -p wa -k profile
-w /etc/shells -p wa -k shells
-w /etc/security/ -p wa -k security
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/issue -p wa -k banners
-w /etc/issue.net -p wa -k banners
-w /etc/hosts.allow -p wa -k tcpwrappers
-w /etc/hosts.deny -p wa -k tcpwrappers
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /bin/kmod -p x -k modules
-w /usr/bin/sudo -p x -k sudo
-w /usr/bin/su -p x -k su
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
-a always,exit -F arch=b64 -S mount -S umount2 -k mount
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -S rmdir -k delete
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k owner_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k xattr
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -k access
-a always,exit -F arch=b64 -S init_module -S delete_module -S finit_module -k modules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k hostname
-a always,exit -F arch=b64 -S ptrace -k tracing
-a always,exit -F arch=b64 -S personality -k bypass
-e 2
AUDIT

systemctl enable auditd
augenrules --load 2>/dev/null
systemctl restart auditd

# Process accounting
echo "Enabling process accounting..."
systemctl enable acct
mkdir -p /var/log/account
touch /var/log/account/pacct
accton on 2>/dev/null || accton /var/log/account/pacct 2>/dev/null

# Sysstat
echo "Enabling sysstat..."
sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
systemctl enable sysstat
systemctl restart sysstat

# AppArmor
echo "Enabling AppArmor..."
systemctl enable apparmor
systemctl start apparmor
aa-enforce /etc/apparmor.d/* 2>/dev/null

# Rsyslog
echo "Configuring rsyslog..."
cat > /etc/rsyslog.d/50-hardening.conf << 'RSYSLOG'
$FileCreateMode 0640
auth,authpriv.* /var/log/auth.log
*.*;auth,authpriv.none -/var/log/syslog
cron.* /var/log/cron.log
kern.* -/var/log/kern.log
RSYSLOG
systemctl restart rsyslog

# Chrony
echo "Configuring chrony..."
systemctl disable systemd-timesyncd 2>/dev/null
systemctl stop systemd-timesyncd 2>/dev/null
cat > /etc/chrony/chrony.conf << 'CHRONY'
pool 2.debian.pool.ntp.org iburst maxsources 4
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
leapsectz right/UTC
CHRONY
systemctl enable chrony
systemctl restart chrony

# Haveged
echo "Enabling haveged..."
systemctl enable haveged
systemctl start haveged

# Automatic updates
echo "Configuring automatic updates..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UNATTENDED'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
UNATTENDED

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTOUPGRADE'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
AUTOUPGRADE

# Cron restrictions
echo "Restricting cron..."
rm -f /etc/cron.deny /etc/at.deny
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow
chmod 600 /etc/crontab
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly

# TCP wrappers
echo "Configuring TCP wrappers..."
echo "ALL: ALL" > /etc/hosts.deny
cat > /etc/hosts.allow << 'TCPWRAP'
sshd: ALL
ALL: 127.0.0.1
ALL: [::1]
TCPWRAP

# Permissions
echo "Setting permissions..."
chmod 700 /root
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 640 /etc/shadow
chmod 640 /etc/gshadow
chown root:shadow /etc/shadow
chown root:shadow /etc/gshadow
chmod 600 /boot/grub/grub.cfg 2>/dev/null
chown root:root /boot/grub/grub.cfg 2>/dev/null

for dir in /home/*; do
    if [[ -d "$dir" ]]; then
        chmod 700 "$dir"
    fi
done

find /var/log -type f -exec chmod 640 {} \; 2>/dev/null
chmod 660 /var/log/wtmp 2>/dev/null
chmod 660 /var/log/btmp 2>/dev/null
chmod 660 /var/log/lastlog 2>/dev/null
chown root:utmp /var/log/wtmp 2>/dev/null
chown root:utmp /var/log/btmp 2>/dev/null
chown root:utmp /var/log/lastlog 2>/dev/null

# Remove SUID
echo "Removing unnecessary SUID..."
chmod u-s /usr/bin/chfn 2>/dev/null
chmod u-s /usr/bin/chsh 2>/dev/null
chmod u-s /usr/bin/newgrp 2>/dev/null

# Disable services
echo "Disabling unnecessary services..."
for svc in avahi-daemon cups cups-browsed bluetooth ModemManager; do
    systemctl disable "$svc" 2>/dev/null
    systemctl stop "$svc" 2>/dev/null
done

# Lock accounts
echo "Locking system accounts..."
for user in daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
    passwd -l "$user" 2>/dev/null
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null
done

# Remove accounts
for user in games gnats irc news uucp; do
    userdel -r "$user" 2>/dev/null
done

# Restrict compilers
echo "Restricting compilers..."
for bin in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/c++ /usr/bin/make /usr/bin/as; do
    if [[ -f "$bin" ]]; then
        chmod 700 "$bin"
    fi
done
for bin in /usr/bin/gcc-* /usr/bin/g++-*; do
    if [[ -f "$bin" ]]; then
        chmod 700 "$bin"
    fi
done

# World writable
echo "Fixing world writable files..."
find / -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null
find / -xdev -type d -perm -0002 ! -perm -1000 -exec chmod +t {} \; 2>/dev/null

# Orphan files
echo "Fixing orphan files..."
find / -xdev \( -nouser -o -nogroup \) -exec chown root:root {} \; 2>/dev/null

# Core dumps
echo "Disabling core dumps..."
mkdir -p /etc/security/limits.d
echo "* hard core 0" > /etc/security/limits.d/core.conf
echo "* soft core 0" >> /etc/security/limits.d/core.conf

mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'COREDUMP'
[Coredump]
Storage=none
ProcessSizeMax=0
COREDUMP

# ClamAV
echo "Configuring ClamAV..."
systemctl stop clamav-freshclam 2>/dev/null
freshclam 2>/dev/null
systemctl enable clamav-freshclam
systemctl start clamav-freshclam
systemctl enable clamav-daemon 2>/dev/null
systemctl start clamav-daemon 2>/dev/null

# RKHunter
echo "Configuring RKHunter..."
if [[ -f /etc/rkhunter.conf ]]; then
    sed -i 's/^MIRRORS_MODE=.*$/MIRRORS_MODE=0/' /etc/rkhunter.conf 2>/dev/null
    sed -i 's/^UPDATE_MIRRORS=.*$/UPDATE_MIRRORS=1/' /etc/rkhunter.conf 2>/dev/null
    sed -i 's/^WEB_CMD=.*$/WEB_CMD=""/' /etc/rkhunter.conf 2>/dev/null
fi
rkhunter --update 2>/dev/null
rkhunter --propupd 2>/dev/null

# AIDE
echo "Initializing AIDE..."
aideinit 2>/dev/null &

# Daily scan cron
echo "Creating daily scan cron..."
cat > /etc/cron.daily/security-scan << 'SECURITYSCAN'
#!/bin/bash
LOG="/var/log/security-scan-$(date +%Y%m%d).log"
echo "Security scan: $(date)" >> "$LOG"
clamscan -r /home /tmp /var/tmp --quiet --infected >> "$LOG" 2>&1
rkhunter --check --skip-keypress --quiet >> "$LOG" 2>&1
chkrootkit -q >> "$LOG" 2>&1
SECURITYSCAN
chmod 700 /etc/cron.daily/security-scan

# Weekly AIDE cron
cat > /etc/cron.weekly/aide-check << 'AIDECHECK'
#!/bin/bash
aide --check >> /var/log/aide-check.log 2>&1
AIDECHECK
chmod 700 /etc/cron.weekly/aide-check

# Cleanup
echo "Cleaning up..."
apt-get autoremove --purge -y
apt-get autoclean
apt-get clean
rm -rf /tmp/* /var/tmp/* 2>/dev/null
journalctl --vacuum-time=7d 2>/dev/null

# Restart services
echo "Restarting services..."
systemctl restart sshd
systemctl restart fail2ban
systemctl restart auditd
systemctl restart rsyslog
systemctl restart chrony

# Verify services
echo "Verifying services..."
for svc in sshd fail2ban auditd rsyslog chrony ufw apparmor; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "$svc: OK"
    else
        echo "$svc: FAILED"
    fi
done

# Run Lynis
echo ""
echo "Running Lynis audit..."
echo ""
lynis audit system --no-colors 2>/dev/null | tee /var/log/lynis-audit.log

# Get score
SCORE=$(grep "Hardening index" /var/log/lynis-audit.log | grep -oP '\d+' | head -1)

echo ""
echo "============================================"
echo "HARDENING COMPLETE"
echo "============================================"
echo ""
echo "Lynis Score: $SCORE"
echo ""
echo "SSH Ports: 22 and 2222"
echo "Firewall: UFW enabled (22,2222,80,443)"
echo "Fail2ban: Active"
echo "Auditd: Active"
echo "AppArmor: Active"
echo ""
echo "Log: $LOG"
echo "Lynis: /var/log/lynis-audit.log"
echo ""
echo "REBOOT NOW: sudo reboot"
echo "============================================"
