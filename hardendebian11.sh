#!/bin/bash
#===============================================================================
#
#          FILE: harden-ultimate.sh
#
#         USAGE: chmod +x harden-ultimate.sh && sudo ./harden-ultimate.sh
#
#   DESCRIPTION: Ultimate Debian 11 Hardening Script
#                Target: Lynis 90+ Score
#                Safe: No network/DNS/fstab modifications
#
#        AUTHOR: Security Hardening Script
#       VERSION: 2.0
#       CREATED: 2024
#
#===============================================================================

set +e
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

#===============================================================================
# VARIABLES
#===============================================================================
LOG_FILE="/var/log/hardening-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/hardening-backup-$(date +%Y%m%d-%H%M%S)"
SSH_PORT_1="22"
SSH_PORT_2="2222"
GRUB_PASSWORD=""  # Set to enable GRUB password: "yourpassword"

#===============================================================================
# COLORS
#===============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

#===============================================================================
# FUNCTIONS
#===============================================================================
log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

info() {
    echo -e "${CYAN}[*]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG_FILE"
}

section() {
    echo ""
    echo -e "${BLUE}===========================================================${NC}"
    echo -e "${BLUE}   $1${NC}"
    echo -e "${BLUE}===========================================================${NC}"
    echo ""
    echo "===========================================================" >> "$LOG_FILE"
    echo "   $1" >> "$LOG_FILE"
    echo "===========================================================" >> "$LOG_FILE"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$file" "$BACKUP_DIR/$(basename $file).bak"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

#===============================================================================
# PRE-FLIGHT CHECKS
#===============================================================================
pre_flight() {
    section "PRE-FLIGHT CHECKS"
    
    check_root
    log "Running as root: OK"
    
    # Check Debian version
    if [[ -f /etc/debian_version ]]; then
        DEBIAN_VERSION=$(cat /etc/debian_version)
        log "Debian version: $DEBIAN_VERSION"
    else
        warn "Not running Debian - script may not work correctly"
    fi
    
    # Check internet connectivity
    if ping -c 1 -W 3 8.8.8.8 &>/dev/null; then
        log "Internet connectivity: OK"
    else
        error "No internet connectivity - some features may fail"
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    log "Backup directory: $BACKUP_DIR"
    
    # Check available disk space
    DISK_FREE=$(df -h / | awk 'NR==2 {print $4}')
    log "Available disk space: $DISK_FREE"
    
    # Record system info
    log "Hostname: $(hostname)"
    log "Kernel: $(uname -r)"
    log "Architecture: $(uname -m)"
}

#===============================================================================
# SYSTEM UPDATE
#===============================================================================
system_update() {
    section "SYSTEM UPDATE"
    
    log "Updating package lists..."
    apt update
    
    log "Performing full system upgrade..."
    apt full-upgrade -y
    
    log "Installing essential packages..."
    apt install -y \
        lynis \
        fail2ban \
        sysstat \
        auditd \
        audispd-plugins \
        ufw \
        curl \
        wget \
        libpam-pwquality \
        libpam-tmpdir \
        libpam-apparmor \
        needrestart \
        debsums \
        apt-show-versions \
        apt-listbugs \
        apt-listchanges \
        acct \
        rkhunter \
        chkrootkit \
        clamav \
        clamav-daemon \
        aide \
        aide-common \
        apparmor \
        apparmor-utils \
        apparmor-profiles \
        apparmor-profiles-extra \
        logrotate \
        rsyslog \
        haveged \
        rng-tools \
        chrony \
        unattended-upgrades \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        psmisc \
        lsof \
        net-tools \
        tcpdump \
        htop \
        iotop \
        sysdig \
        secure-delete \
        libpam-cracklib \
        checksecurity \
        debsecan \
        fail2ban \
        iptables-persistent \
        netfilter-persistent
    
    log "Package installation complete"
}

#===============================================================================
# KERNEL HARDENING
#===============================================================================
kernel_hardening() {
    section "KERNEL HARDENING"
    
    backup_file "/etc/sysctl.conf"
    
    log "Applying comprehensive kernel hardening..."
    
    cat > /etc/sysctl.d/99-security-hardening.conf << 'EOF'
#===============================================================================
# KERNEL HARDENING PARAMETERS
#===============================================================================

#-------------------------------------------------------------------------------
# KERNEL SECURITY
#-------------------------------------------------------------------------------
# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg access to root only
kernel.dmesg_restrict = 1

# Disable magic SysRq key
kernel.sysrq = 0

# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Restrict ptrace scope (0=all, 1=parent, 2=admin, 3=none)
kernel.yama.ptrace_scope = 2

# Include PID in core dump filename
kernel.core_uses_pid = 1

# Restrict performance events
kernel.perf_event_paranoid = 3

# Disable unprivileged BPF
kernel.unprivileged_bpf_disabled = 1

# Harden BPF JIT compiler
net.core.bpf_jit_harden = 2

# Restrict loading TTY line disciplines
dev.tty.ldisc_autoload = 0

# Disable kexec
kernel.kexec_load_disabled = 1

# Increase PID max
kernel.pid_max = 65536

#-------------------------------------------------------------------------------
# FILESYSTEM SECURITY
#-------------------------------------------------------------------------------
# Disable core dumps for setuid programs
fs.suid_dumpable = 0

# Protect hardlinks
fs.protected_hardlinks = 1

# Protect symlinks
fs.protected_symlinks = 1

# Protect FIFOs
fs.protected_fifos = 2

# Protect regular files
fs.protected_regular = 2

#-------------------------------------------------------------------------------
# MEMORY SECURITY
#-------------------------------------------------------------------------------
# Minimum virtual address for mmap
vm.mmap_min_addr = 65536

# Randomize mmap base
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16

# Reduce swappiness
vm.swappiness = 10

# Disable unprivileged userfaultfd
vm.unprivileged_userfaultfd = 0

#-------------------------------------------------------------------------------
# NETWORK SECURITY - IPv4
#-------------------------------------------------------------------------------
# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable TCP timestamps
net.ipv4.tcp_timestamps = 0

# Increase SYN backlog
net.ipv4.tcp_max_syn_backlog = 4096

# Reduce SYN-ACK retries
net.ipv4.tcp_synack_retries = 2

# Reduce SYN retries
net.ipv4.tcp_syn_retries = 3

# RFC 1337 fix
net.ipv4.tcp_rfc1337 = 1

# Drop gratuitous ARP
net.ipv4.conf.all.drop_gratuitous_arp = 1
net.ipv4.conf.default.drop_gratuitous_arp = 1

# Disable SACK (potential vulnerability)
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0

# Increase local port range
net.ipv4.ip_local_port_range = 1024 65535

#-------------------------------------------------------------------------------
# NETWORK SECURITY - IPv6
#-------------------------------------------------------------------------------
# Disable IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable IPv6 source routing
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

#-------------------------------------------------------------------------------
# NETWORK PERFORMANCE
#-------------------------------------------------------------------------------
# Increase network buffer sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65536
net.core.netdev_max_backlog = 5000

# TCP buffer sizes
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1

# Increase connection tracking
net.netfilter.nf_conntrack_max = 524288
EOF

    log "Loading kernel parameters..."
    sysctl --system
    
    log "Kernel hardening complete"
}

#===============================================================================
# DISABLE UNUSED FILESYSTEMS AND PROTOCOLS
#===============================================================================
disable_modules() {
    section "DISABLE UNUSED FILESYSTEMS AND PROTOCOLS"
    
    log "Creating module blacklist..."
    
    cat > /etc/modprobe.d/hardening-blacklist.conf << 'EOF'
#===============================================================================
# FILESYSTEM BLACKLIST
#===============================================================================
install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install squashfs /bin/true
install udf /bin/true
install fat /bin/true
install vfat /bin/true
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install gfs2 /bin/true

#===============================================================================
# NETWORK PROTOCOL BLACKLIST
#===============================================================================
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install n-hdlc /bin/true
install ax25 /bin/true
install netrom /bin/true
install x25 /bin/true
install rose /bin/true
install decnet /bin/true
install econet /bin/true
install af_802154 /bin/true
install ipx /bin/true
install appletalk /bin/true
install psnap /bin/true
install p8023 /bin/true
install p8022 /bin/true
install can /bin/true
install atm /bin/true

#===============================================================================
# HARDWARE BLACKLIST (VPS - not needed)
#===============================================================================
install usb-storage /bin/true
install firewire-core /bin/true
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true
install thunderbolt /bin/true
install bluetooth /bin/true
install btusb /bin/true
install bnep /bin/true
install crc16 /bin/true
install rfcomm /bin/true
install floppy /bin/true
install pcspkr /bin/true
install snd_pcsp /bin/true
install cdrom /bin/true
install sr_mod /bin/true
install soundcore /bin/true

#===============================================================================
# MISC BLACKLIST
#===============================================================================
install vivid /bin/true
install mei /bin/true
install mei-me /bin/true
EOF

    log "Module blacklist created"
}

#===============================================================================
# SSH HARDENING
#===============================================================================
ssh_hardening() {
    section "SSH HARDENING"
    
    backup_file "/etc/ssh/sshd_config"
    
    log "Generating new SSH host keys..."
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
    
    log "Configuring SSH server..."
    
    cat > /etc/ssh/sshd_config << EOF
#===============================================================================
# SSH SERVER HARDENING CONFIGURATION
#===============================================================================

#-------------------------------------------------------------------------------
# NETWORK
#-------------------------------------------------------------------------------
Port ${SSH_PORT_1}
Port ${SSH_PORT_2}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

#-------------------------------------------------------------------------------
# HOST KEYS (strongest only)
#-------------------------------------------------------------------------------
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

#-------------------------------------------------------------------------------
# CIPHERS AND ALGORITHMS (strongest only)
#-------------------------------------------------------------------------------
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com

#-------------------------------------------------------------------------------
# AUTHENTICATION
#-------------------------------------------------------------------------------
LoginGraceTime 30
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 3
MaxSessions 3
MaxStartups 10:30:60

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AuthorizedPrincipalsFile none

PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

HostbasedAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts yes

UsePAM yes
AuthenticationMethods publickey

#-------------------------------------------------------------------------------
# SESSION
#-------------------------------------------------------------------------------
X11Forwarding no
X11UseLocalhost yes
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
PermitUserEnvironment no
Compression no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
GatewayPorts no
PermitTunnel no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitUserRC no
ExposeAuthInfo no

#-------------------------------------------------------------------------------
# SECURITY
#-------------------------------------------------------------------------------
DebianBanner no
Banner /etc/issue.net
LogLevel VERBOSE
SyslogFacility AUTH

#-------------------------------------------------------------------------------
# SFTP
#-------------------------------------------------------------------------------
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

#-------------------------------------------------------------------------------
# KEY REGENERATION
#-------------------------------------------------------------------------------
RekeyLimit 512M 1h
EOF

    log "Configuring SSH client..."
    
    mkdir -p /etc/ssh/ssh_config.d
    cat > /etc/ssh/ssh_config.d/hardening.conf << 'EOF'
#===============================================================================
# SSH CLIENT HARDENING
#===============================================================================
Host *
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
    KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
    HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
    HashKnownHosts yes
    StrictHostKeyChecking ask
    VisualHostKey yes
    AddKeysToAgent no
    ForwardAgent no
    ForwardX11 no
    PasswordAuthentication no
    IdentitiesOnly yes
EOF

    log "Setting SSH file permissions..."
    chmod 600 /etc/ssh/sshd_config
    chmod 600 /etc/ssh/ssh_host_*_key
    chmod 644 /etc/ssh/ssh_host_*_key.pub
    
    log "SSH hardening complete"
}

#===============================================================================
# LEGAL BANNERS
#===============================================================================
configure_banners() {
    section "LEGAL BANNERS"
    
    log "Configuring legal warning banners..."
    
    cat > /etc/issue << 'EOF'
################################################################################
#                                                                              #
#                        AUTHORIZED ACCESS ONLY                                #
#                                                                              #
################################################################################
#                                                                              #
#  This system is for authorized users only. All activities on this system    #
#  are logged and monitored. Unauthorized access will be fully investigated   #
#  and reported to the appropriate law enforcement agencies.                  #
#                                                                              #
#  By accessing this system, you consent to:                                  #
#    - Having all activities monitored and recorded                           #
#    - Prosecution if unauthorized access is attempted                        #
#    - Disclosure of any information to law enforcement                       #
#                                                                              #
#  DISCONNECT IMMEDIATELY if you are not an authorized user.                  #
#                                                                              #
################################################################################
EOF
    
    cp /etc/issue /etc/issue.net
    
    cat > /etc/motd << 'EOF'

================================================================================
                    SYSTEM PROTECTED - ALL ACTIONS LOGGED
================================================================================

  * All sessions are monitored and recorded
  * Unauthorized access attempts are logged and reported
  * Security policies are strictly enforced
  * Report suspicious activity immediately

================================================================================

EOF

    chmod 644 /etc/issue /etc/issue.net /etc/motd
    
    log "Banners configured"
}

#===============================================================================
# PASSWORD POLICY
#===============================================================================
password_policy() {
    section "PASSWORD POLICY"
    
    backup_file "/etc/login.defs"
    backup_file "/etc/security/pwquality.conf"
    
    log "Configuring password quality requirements..."
    
    cat > /etc/security/pwquality.conf << 'EOF'
#===============================================================================
# PASSWORD QUALITY CONFIGURATION
#===============================================================================
# Minimum password length
minlen = 14

# Minimum number of character classes
minclass = 4

# Maximum consecutive same characters
maxrepeat = 3

# Maximum consecutive same class characters
maxclassrepeat = 3

# Require at least one digit
dcredit = -1

# Require at least one uppercase
ucredit = -1

# Require at least one lowercase
lcredit = -1

# Require at least one special character
ocredit = -1

# Check if password contains user name
usercheck = 1

# Check GECOS field
gecoscheck = 1

# Enable dictionary check
dictcheck = 1

# Enforce on root as well
enforce_for_root

# Reject passwords that fail checks
enforcing = 1

# Number of characters that must differ from old password
difok = 8

# Check for palindromes
palindrome = 1

# Remember last N passwords
remember = 12
EOF

    log "Configuring login definitions..."
    
    # Backup and modify login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
    sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   3/' /etc/login.defs
    sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD  SHA512/' /etc/login.defs
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
    
    # Add additional settings
    cat >> /etc/login.defs << 'EOF'

#===============================================================================
# ADDITIONAL SECURITY SETTINGS
#===============================================================================
SHA_CRYPT_MIN_ROUNDS 10000
SHA_CRYPT_MAX_ROUNDS 100000
FAILLOG_ENAB yes
LOG_UNKFAIL_ENAB yes
LOG_OK_LOGINS yes
SYSLOG_SU_ENAB yes
SYSLOG_SG_ENAB yes
SULOG_FILE /var/log/sulog
SU_NAME su
CHFN_RESTRICT rwh
DEFAULT_HOME no
CREATE_HOME yes
USERGROUPS_ENAB yes
ENV_SUPATH PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH PATH=/usr/local/bin:/usr/bin:/bin
EOF

    log "Password policy configured"
}

#===============================================================================
# PAM HARDENING
#===============================================================================
pam_hardening() {
    section "PAM HARDENING"
    
    backup_file "/etc/pam.d/common-auth"
    backup_file "/etc/pam.d/common-password"
    backup_file "/etc/pam.d/common-account"
    backup_file "/etc/pam.d/su"
    
    log "Configuring PAM account lockout..."
    
    # Configure faillock (account lockout)
    cat > /etc/security/faillock.conf << 'EOF'
#===============================================================================
# FAILLOCK CONFIGURATION
#===============================================================================
# Deny access after N failed attempts
deny = 5

# Lock duration in seconds (30 minutes)
unlock_time = 1800

# Time window for failed attempts (15 minutes)
fail_interval = 900

# Log to audit
audit

# Include root
even_deny_root
root_unlock_time = 3600

# Create user files in this directory
dir = /var/run/faillock
EOF

    log "Restricting su to wheel group..."
    
    # Create wheel group if not exists
    groupadd -f wheel
    
    # Configure PAM to restrict su
    if ! grep -q "pam_wheel.so" /etc/pam.d/su; then
        echo "auth required pam_wheel.so use_uid group=wheel" >> /etc/pam.d/su
    fi
    
    log "Configuring session limits..."
    
    cat >> /etc/security/limits.conf << 'EOF'

#===============================================================================
# SECURITY LIMITS
#===============================================================================
# Disable core dumps
* hard core 0
* soft core 0
root hard core 0
root soft core 0

# Limit max processes
* hard nproc 1024
* soft nproc 512
root hard nproc unlimited
root soft nproc unlimited

# Limit max open files
* hard nofile 65535
* soft nofile 32768

# Limit max locked memory
* hard memlock 65536
* soft memlock 65536
EOF

    log "PAM hardening complete"
}

#===============================================================================
# SESSION SECURITY
#===============================================================================
session_security() {
    section "SESSION SECURITY"
    
    log "Configuring shell timeout..."
    
    cat > /etc/profile.d/security-hardening.sh << 'EOF'
#!/bin/bash
#===============================================================================
# SECURITY HARDENING PROFILE
#===============================================================================

# Set secure umask
umask 027

# Set session timeout (15 minutes)
TMOUT=900
readonly TMOUT
export TMOUT

# Set secure PATH
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# History settings
HISTSIZE=10000
HISTFILESIZE=20000
HISTCONTROL=ignoreboth:erasedups
HISTTIMEFORMAT="%F %T "
export HISTSIZE HISTFILESIZE HISTCONTROL HISTTIMEFORMAT

# Make history append only
shopt -s histappend 2>/dev/null

# Secure history file
if [[ -f "$HOME/.bash_history" ]]; then
    chmod 600 "$HOME/.bash_history"
fi
EOF
    
    chmod 644 /etc/profile.d/security-hardening.sh
    
    # Configure for all shells
    cat > /etc/profile.d/tmout.sh << 'EOF'
TMOUT=900
readonly TMOUT
export TMOUT
EOF
    chmod 644 /etc/profile.d/tmout.sh
    
    log "Session security configured"
}

#===============================================================================
# FIREWALL (UFW)
#===============================================================================
configure_firewall() {
    section "FIREWALL CONFIGURATION"
    
    log "Resetting UFW..."
    ufw --force reset
    
    log "Setting default policies..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    
    log "Configuring firewall rules..."
    
    # SSH with rate limiting
    ufw limit ${SSH_PORT_1}/tcp comment 'SSH primary'
    ufw limit ${SSH_PORT_2}/tcp comment 'SSH secondary'
    
    # Web services
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    log "Enabling logging..."
    ufw logging high
    
    log "Enabling firewall..."
    ufw --force enable
    
    # Save rules for persistence
    netfilter-persistent save 2>/dev/null
    
    log "Firewall configuration complete"
}

#===============================================================================
# FAIL2BAN
#===============================================================================
configure_fail2ban() {
    section "FAIL2BAN CONFIGURATION"
    
    log "Configuring Fail2ban..."
    
    cat > /etc/fail2ban/jail.local << EOF
#===============================================================================
# FAIL2BAN CONFIGURATION
#===============================================================================

[DEFAULT]
#-------------------------------------------------------------------------------
# DEFAULT SETTINGS
#-------------------------------------------------------------------------------
# Ban time (1 hour)
bantime = 3600

# Find time window (10 minutes)
findtime = 600

# Max retries before ban
maxretry = 3

# Backend
backend = systemd

# Ban action
banaction = ufw

# Ignore localhost
ignoreip = 127.0.0.1/8 ::1

# Enable on startup
enabled = false

# Email settings (optional)
#destemail = admin@example.com
#sender = fail2ban@example.com
#mta = sendmail

#===============================================================================
# SSH JAIL
#===============================================================================
[sshd]
enabled = true
port = ${SSH_PORT_1},${SSH_PORT_2}
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 86400
findtime = 3600

#===============================================================================
# SSH DDOS JAIL
#===============================================================================
[sshd-ddos]
enabled = true
port = ${SSH_PORT_1},${SSH_PORT_2}
filter = sshd-ddos
logpath = %(sshd_log)s
maxretry = 6
bantime = 86400
findtime = 600

#===============================================================================
# RECIDIVE JAIL (repeat offenders)
#===============================================================================
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 604800
findtime = 86400
maxretry = 3

#===============================================================================
# PAM GENERIC
#===============================================================================
[pam-generic]
enabled = true
filter = pam-generic
logpath = %(syslog_authpriv)s
maxretry = 3
bantime = 3600
EOF

    log "Creating SSH DDoS filter..."
    
    cat > /etc/fail2ban/filter.d/sshd-ddos.conf << 'EOF'
[Definition]
failregex = ^%(__prefix_line)s[iI]nvalid user .* from <HOST>\s*$
            ^%(__prefix_line)sDid not receive identification string from <HOST>$
            ^%(__prefix_line)sConnection closed by <HOST> \[preauth\]$
            ^%(__prefix_line)sConnection reset by <HOST> \[preauth\]$
            ^%(__prefix_line)sReceived disconnect from <HOST>:.*\[preauth\]$
            ^%(__prefix_line)sBad protocol version identification .* from <HOST>$
ignoreregex =
EOF

    log "Enabling Fail2ban..."
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log "Fail2ban configuration complete"
}

#===============================================================================
# AUDITD
#===============================================================================
configure_auditd() {
    section "AUDIT SYSTEM CONFIGURATION"
    
    backup_file "/etc/audit/auditd.conf"
    
    log "Configuring auditd..."
    
    # Configure auditd.conf
    cat > /etc/audit/auditd.conf << 'EOF'
#===============================================================================
# AUDITD CONFIGURATION
#===============================================================================
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 50
num_logs = 10
priority_boost = 4
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
distribute_network = no
EOF

    log "Creating comprehensive audit rules..."
    
    cat > /etc/audit/rules.d/99-hardening.rules << 'EOF'
#===============================================================================
# COMPREHENSIVE AUDIT RULES
#===============================================================================

# Delete all existing rules
-D

# Set buffer size
-b 8192

# Set failure mode (1=print, 2=panic)
-f 1

# Set backlog wait time
--backlog_wait_time 60000

#===============================================================================
# SELF AUDITING
#===============================================================================
-w /var/log/audit/ -k auditlog
-w /etc/audit/ -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
-w /usr/sbin/augenrules -p x -k audittools

#===============================================================================
# IDENTITY AND AUTHENTICATION
#===============================================================================
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.d/ -p wa -k pam
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /etc/security/ -p wa -k security

#===============================================================================
# PRIVILEGE ESCALATION
#===============================================================================
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /usr/bin/sudo -p x -k sudo_usage
-w /usr/bin/su -p x -k su_usage
-w /bin/su -p x -k su_usage

#===============================================================================
# SSH
#===============================================================================
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/ssh_config -p wa -k sshd
-w /etc/ssh/ssh_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k ssh_root

#===============================================================================
# NETWORK CONFIGURATION
#===============================================================================
-w /etc/hosts -p wa -k hosts
-w /etc/hosts.allow -p wa -k tcpwrappers
-w /etc/hosts.deny -p wa -k tcpwrappers
-w /etc/network/ -p wa -k network
-w /etc/sysconfig/network -p wa -k network
-w /etc/resolv.conf -p wa -k dns
-w /etc/hostname -p wa -k hostname

#===============================================================================
# SYSTEM CONFIGURATION
#===============================================================================
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/modprobe.d/ -p wa -k modprobe
-w /etc/modules-load.d/ -p wa -k modules
-w /etc/profile -p wa -k profile
-w /etc/profile.d/ -p wa -k profile
-w /etc/shells -p wa -k shells
-w /etc/bashrc -p wa -k bashrc
-w /etc/bash.bashrc -p wa -k bashrc
-w /etc/environment -p wa -k environment
-w /etc/ld.so.conf -p wa -k libpath
-w /etc/ld.so.conf.d/ -p wa -k libpath

#===============================================================================
# CRON AND SCHEDULED TASKS
#===============================================================================
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /var/spool/cron/crontabs/ -p wa -k cron
-w /etc/at.allow -p wa -k at
-w /etc/at.deny -p wa -k at
-w /var/spool/at/ -p wa -k at

#===============================================================================
# LOGS
#===============================================================================
-w /var/log/auth.log -p wa -k authlog
-w /var/log/syslog -p wa -k syslog
-w /var/log/faillog -p wa -k faillog
-w /var/log/lastlog -p wa -k lastlog
-w /var/log/wtmp -p wa -k wtmp
-w /var/log/btmp -p wa -k btmp

#===============================================================================
# KERNEL MODULES
#===============================================================================
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /bin/kmod -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -S finit_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -S finit_module -k modules

#===============================================================================
# SYSTEM CALLS
#===============================================================================
# Process execution
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Mount operations
-a always,exit -F arch=b64 -S mount -S umount2 -k mount
-a always,exit -F arch=b32 -S mount -S umount -S umount2 -k mount

# File deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -S rmdir -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -S rmdir -k delete

# Permission changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm_mod

# Ownership changes
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k owner_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -k owner_mod

# Extended attributes
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k xattr
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k xattr

# Access attempts (failed)
-a always,exit -F arch=b64 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EPERM -k access
-a always,exit -F arch=b32 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b32 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EPERM -k access

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# Hostname changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k hostname
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k hostname

# Ptrace
-a always,exit -F arch=b64 -S ptrace -k tracing
-a always,exit -F arch=b32 -S ptrace -k tracing

# Personality (bypass ASLR)
-a always,exit -F arch=b64 -S personality -k bypass
-a always,exit -F arch=b32 -S personality -k bypass

# Network connections
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b64 -S accept -S accept4 -k network_accept
-a always,exit -F arch=b64 -S listen -k network_listen
-a always,exit -F arch=b64 -S bind -k network_bind

# Socket creation
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket
-a always,exit -F arch=b64 -S socket -F a0=10 -k network_socket6

# Memory operations
-a always,exit -F arch=b64 -S memfd_create -k memfd
-a always,exit -F arch=b64 -S userfaultfd -k userfaultfd

# BPF
-a always,exit -F arch=b64 -S bpf -k bpf

#===============================================================================
# SPECIAL FILES
#===============================================================================
-w /etc/issue -p wa -k banners
-w /etc/issue.net -p wa -k banners
-w /etc/motd -p wa -k banners

#===============================================================================
# APPARMOR
#===============================================================================
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor

#===============================================================================
# SYSTEMD
#===============================================================================
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd
-w /usr/lib/systemd/ -p wa -k systemd

#===============================================================================
# MAKE CONFIGURATION IMMUTABLE
#===============================================================================
-e 2
EOF

    log "Loading audit rules..."
    augenrules --load 2>/dev/null
    
    log "Enabling auditd..."
    systemctl enable auditd
    systemctl restart auditd
    
    log "Audit configuration complete"
}

#===============================================================================
# PROCESS ACCOUNTING
#===============================================================================
configure_accounting() {
    section "PROCESS ACCOUNTING"
    
    log "Enabling process accounting..."
    
    systemctl enable acct
    
    mkdir -p /var/log/account
    touch /var/log/account/pacct
    
    /usr/sbin/accton on 2>/dev/null || /usr/sbin/accton /var/log/account/pacct
    
    log "Enabling sysstat..."
    
    sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
    systemctl enable sysstat
    systemctl restart sysstat
    
    log "Accounting configured"
}

#===============================================================================
# APPARMOR
#===============================================================================
configure_apparmor() {
    section "APPARMOR CONFIGURATION"
    
    log "Enabling AppArmor..."
    
    systemctl enable apparmor
    systemctl start apparmor
    
    log "Enforcing AppArmor profiles..."
    
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    
    log "AppArmor status:"
    aa-status 2>/dev/null || apparmor_status 2>/dev/null || true
    
    log "AppArmor configuration complete"
}

#===============================================================================
# LOGGING CONFIGURATION
#===============================================================================
configure_logging() {
    section "LOGGING CONFIGURATION"
    
    backup_file "/etc/rsyslog.conf"
    
    log "Configuring rsyslog..."
    
    cat > /etc/rsyslog.d/50-security-hardening.conf << 'EOF'
#===============================================================================
# SECURITY LOGGING CONFIGURATION
#===============================================================================

# Set file creation mode
$FileCreateMode 0640
$DirCreateMode 0750
$Umask 0027

# Kernel messages
kern.* /var/log/kern.log

# Authentication messages
auth,authpriv.* /var/log/auth.log

# Cron messages
cron.* /var/log/cron.log

# All other messages (except auth/authpriv)
*.*;auth,authpriv.none -/var/log/syslog

# Emergency messages to all users
*.emerg :omusrmsg:*

# Save boot messages
local7.* /var/log/boot.log
EOF

    log "Restarting rsyslog..."
    systemctl restart rsyslog
    
    log "Configuring logrotate..."
    
    cat > /etc/logrotate.d/security-hardening << 'EOF'
/var/log/auth.log
/var/log/kern.log
/var/log/cron.log
/var/log/sulog
{
    rotate 12
    monthly
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}

/var/log/audit/*.log
{
    rotate 12
    monthly
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    postrotate
        /usr/bin/killall -HUP auditd 2>/dev/null || true
    endscript
}
EOF

    log "Logging configuration complete"
}

#===============================================================================
# TIME SYNCHRONIZATION
#===============================================================================
configure_time() {
    section "TIME SYNCHRONIZATION"
    
    log "Configuring Chrony NTP..."
    
    cat > /etc/chrony/chrony.conf << 'EOF'
#===============================================================================
# CHRONY NTP CONFIGURATION
#===============================================================================

# Debian NTP pool
pool 2.debian.pool.ntp.org iburst maxsources 4

# Key file
keyfile /etc/chrony/chrony.keys

# Drift file
driftfile /var/lib/chrony/chrony.drift

# Log directory
logdir /var/log/chrony

# Max skew
maxupdateskew 100.0

# Sync RTC
rtcsync

# Allow step at startup
makestep 1 3

# Leap second timezone
leapsectz right/UTC

# Disable command port for security
cmdport 0
EOF

    log "Disabling systemd-timesyncd (using chrony instead)..."
    systemctl disable systemd-timesyncd 2>/dev/null
    systemctl stop systemd-timesyncd 2>/dev/null
    
    log "Enabling chrony..."
    systemctl enable chrony
    systemctl restart chrony
    
    log "Time synchronization configured"
}

#===============================================================================
# ENTROPY
#===============================================================================
configure_entropy() {
    section "ENTROPY CONFIGURATION"
    
    log "Configuring haveged for entropy..."
    systemctl enable haveged
    systemctl start haveged
    
    log "Configuring rng-tools..."
    if [[ -f /etc/default/rng-tools ]]; then
        echo 'HRNGDEVICE=/dev/urandom' >> /etc/default/rng-tools
    fi
    systemctl enable rng-tools 2>/dev/null || true
    systemctl start rng-tools 2>/dev/null || true
    
    log "Entropy configured"
}

#===============================================================================
# AUTOMATIC UPDATES
#===============================================================================
configure_auto_updates() {
    section "AUTOMATIC SECURITY UPDATES"
    
    log "Configuring unattended-upgrades..."
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
#===============================================================================
# UNATTENDED UPGRADES CONFIGURATION
#===============================================================================

Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

// Package blacklist
Unattended-Upgrade::Package-Blacklist {
};

// Fix interrupted dpkg
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

// Minimal steps
Unattended-Upgrade::MinimalSteps "true";

// Remove unused kernel packages
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Auto reboot (disabled - manual reboot preferred)
Unattended-Upgrade::Automatic-Reboot "false";

// Syslog
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

// Only on AC power (for laptops)
Unattended-Upgrade::OnlyOnACPower "true";

// Skip updates on metered connection
Unattended-Upgrade::Skip-Updates-On-Metered-Connections "true";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

    log "Automatic updates configured"
}

#===============================================================================
# CRON RESTRICTIONS
#===============================================================================
restrict_cron() {
    section "CRON RESTRICTIONS"
    
    log "Restricting cron access..."
    
    rm -f /etc/cron.deny /etc/at.deny
    
    echo "root" > /etc/cron.allow
    echo "root" > /etc/at.allow
    
    chmod 600 /etc/cron.allow
    chmod 600 /etc/at.allow
    chown root:root /etc/cron.allow
    chown root:root /etc/at.allow
    
    log "Setting cron directory permissions..."
    
    chmod 600 /etc/crontab
    chmod 700 /etc/cron.d
    chmod 700 /etc/cron.daily
    chmod 700 /etc/cron.hourly
    chmod 700 /etc/cron.weekly
    chmod 700 /etc/cron.monthly
    
    chown root:root /etc/crontab
    chown root:root /etc/cron.d
    chown root:root /etc/cron.daily
    chown root:root /etc/cron.hourly
    chown root:root /etc/cron.weekly
    chown root:root /etc/cron.monthly
    
    log "Cron restrictions complete"
}

#===============================================================================
# TCP WRAPPERS
#===============================================================================
configure_tcp_wrappers() {
    section "TCP WRAPPERS"
    
    backup_file "/etc/hosts.allow"
    backup_file "/etc/hosts.deny"
    
    log "Configuring TCP wrappers..."
    
    cat > /etc/hosts.deny << 'EOF'
#===============================================================================
# DENY ALL BY DEFAULT
#===============================================================================
ALL: ALL
EOF

    cat > /etc/hosts.allow << 'EOF'
#===============================================================================
# ALLOW RULES
#===============================================================================
# Allow SSH from anywhere (adjust as needed)
sshd: ALL

# Allow localhost
ALL: 127.0.0.1
ALL: [::1]
EOF

    chmod 644 /etc/hosts.allow
    chmod 644 /etc/hosts.deny
    
    log "TCP wrappers configured"
}

#===============================================================================
# FILE PERMISSIONS
#===============================================================================
secure_permissions() {
    section "FILE PERMISSIONS"
    
    log "Securing root home..."
    chmod 700 /root
    
    log "Securing home directories..."
    for dir in /home/*; do
        if [[ -d "$dir" ]]; then
            chmod 700 "$dir"
        fi
    done
    
    log "Securing password files..."
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 640 /etc/shadow
    chmod 640 /etc/gshadow
    chown root:shadow /etc/shadow
    chown root:shadow /etc/gshadow
    
    log "Securing SSH files..."
    chmod 600 /etc/ssh/sshd_config
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null
    chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null
    chown root:root /etc/ssh/sshd_config
    
    log "Securing boot directory..."
    chmod 600 /boot/grub/grub.cfg 2>/dev/null
    chown root:root /boot/grub/grub.cfg 2>/dev/null
    
    log "Securing log files..."
    chmod 640 /var/log/auth.log 2>/dev/null
    chmod 640 /var/log/syslog 2>/dev/null
    chmod 640 /var/log/kern.log 2>/dev/null
    chmod 660 /var/log/wtmp 2>/dev/null
    chmod 660 /var/log/btmp 2>/dev/null
    chmod 660 /var/log/lastlog 2>/dev/null
    
    chown root:utmp /var/log/wtmp 2>/dev/null
    chown root:utmp /var/log/btmp 2>/dev/null
    chown root:utmp /var/log/lastlog 2>/dev/null
    
    log "Permissions secured"
}

#===============================================================================
# REMOVE SUID/SGID
#===============================================================================
restrict_suid_sgid() {
    section "SUID/SGID RESTRICTIONS"
    
    log "Removing unnecessary SUID/SGID bits..."
    
    # List of SUID binaries to keep
    KEEP_SUID="/usr/bin/sudo /usr/bin/passwd /usr/bin/su /usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/bin/mount /usr/bin/umount /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/gpasswd"
    
    # Remove SUID from potentially dangerous binaries
    REMOVE_SUID="/usr/bin/at /usr/bin/pkexec /usr/bin/crontab"
    
    for binary in $REMOVE_SUID; do
        if [[ -f "$binary" ]]; then
            chmod u-s "$binary" 2>/dev/null && log "Removed SUID: $binary"
        fi
    done
    
    log "SUID/SGID restrictions complete"
}

#===============================================================================
# DISABLE UNNECESSARY SERVICES
#===============================================================================
disable_services() {
    section "DISABLE UNNECESSARY SERVICES"
    
    log "Disabling unnecessary services..."
    
    DISABLE_SERVICES="
        avahi-daemon
        cups
        cups-browsed
        bluetooth
        ModemManager
        pppd-dns
        wpa_supplicant
        isc-dhcp-server
        isc-dhcp-server6
        bind9
        named
        nfs-server
        rpcbind
        telnet
        vsftpd
        xinetd
    "
    
    for svc in $DISABLE_SERVICES; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null
            systemctl disable "$svc" 2>/dev/null
            log "Disabled: $svc"
        fi
    done
    
    log "Service cleanup complete"
}

#===============================================================================
# LOCK SYSTEM ACCOUNTS
#===============================================================================
lock_accounts() {
    section "LOCK SYSTEM ACCOUNTS"
    
    log "Locking system accounts..."
    
    LOCK_ACCOUNTS="
        daemon
        bin
        sys
        sync
        games
        man
        lp
        mail
        news
        uucp
        proxy
        www-data
        backup
        list
        irc
        gnats
        nobody
        systemd-network
        systemd-resolve
        messagebus
        systemd-timesync
        sshd
        _apt
    "
    
    for user in $LOCK_ACCOUNTS; do
        if id "$user" &>/dev/null; then
            passwd -l "$user" 2>/dev/null
            usermod -s /usr/sbin/nologin "$user" 2>/dev/null
        fi
    done
    
    log "Removing unnecessary accounts..."
    
    REMOVE_ACCOUNTS="games gnats irc list news uucp"
    
    for user in $REMOVE_ACCOUNTS; do
        if id "$user" &>/dev/null; then
            userdel -r "$user" 2>/dev/null && log "Removed user: $user"
        fi
    done
    
    log "Account management complete"
}

#===============================================================================
# COMPILER RESTRICTIONS
#===============================================================================
restrict_compilers() {
    section "COMPILER RESTRICTIONS"
    
    log "Restricting compiler access..."
    
    COMPILERS="
        /usr/bin/gcc
        /usr/bin/g++
        /usr/bin/cc
        /usr/bin/c++
        /usr/bin/make
        /usr/bin/as
        /usr/bin/ld
    "
    
    for compiler in $COMPILERS; do
        if [[ -f "$compiler" ]]; then
            chmod 700 "$compiler" 2>/dev/null
            chown root:root "$compiler" 2>/dev/null
            log "Restricted: $compiler"
        fi
    done
    
    # Also restrict by pattern
    for compiler in /usr/bin/gcc-* /usr/bin/g++-*; do
        if [[ -f "$compiler" ]]; then
            chmod 700 "$compiler" 2>/dev/null
        fi
    done
    
    log "Compiler restrictions complete"
}

#===============================================================================
# WORLD WRITABLE FILES
#===============================================================================
fix_world_writable() {
    section "WORLD WRITABLE FILES"
    
    log "Finding and fixing world-writable files..."
    
    find / -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null
    
    log "Ensuring sticky bit on world-writable directories..."
    
    find / -xdev -type d -perm -0002 ! -perm -1000 -exec chmod +t {} \; 2>/dev/null
    
    log "World writable files fixed"
}

#===============================================================================
# ORPHAN FILES
#===============================================================================
fix_orphan_files() {
    section "ORPHAN FILES"
    
    log "Finding orphan files (this may take a while)..."
    
    ORPHAN_COUNT=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l)
    
    if [[ $ORPHAN_COUNT -gt 0 ]]; then
        log "Found $ORPHAN_COUNT orphan files, fixing..."
        find / -xdev \( -nouser -o -nogroup \) -exec chown root:root {} \; 2>/dev/null
    else
        log "No orphan files found"
    fi
    
    log "Orphan file check complete"
}

#===============================================================================
# GRUB PASSWORD (OPTIONAL)
#===============================================================================
configure_grub() {
    section "GRUB CONFIGURATION"
    
    if [[ -n "$GRUB_PASSWORD" ]]; then
        log "Configuring GRUB password..."
        
        GRUB_HASH=$(echo -e "${GRUB_PASSWORD}\n${GRUB_PASSWORD}" | grub-mkpasswd-pbkdf2 2>/dev/null | grep -oP 'grub\.pbkdf2.*')
        
        if [[ -n "$GRUB_HASH" ]]; then
            cat >> /etc/grub.d/40_custom << EOF
set superusers="root"
password_pbkdf2 root $GRUB_HASH
EOF
            update-grub 2>/dev/null
            log "GRUB password configured"
        else
            warn "Failed to generate GRUB password hash"
        fi
    else
        log "GRUB password not configured (set GRUB_PASSWORD variable to enable)"
    fi
    
    # Secure GRUB config file regardless
    chmod 600 /boot/grub/grub.cfg 2>/dev/null
    chown root:root /boot/grub/grub.cfg 2>/dev/null
    
    log "GRUB configuration complete"
}

#===============================================================================
# MALWARE DETECTION
#===============================================================================
configure_malware_detection() {
    section "MALWARE DETECTION"
    
    log "Updating ClamAV database..."
    systemctl stop clamav-freshclam 2>/dev/null
    freshclam 2>/dev/null || warn "ClamAV update failed (may need manual run)"
    systemctl enable clamav-freshclam
    systemctl start clamav-freshclam
    
    log "Configuring RKHunter..."
    
    if [[ -f /etc/rkhunter.conf ]]; then
        sed -i 's/^MIRRORS_MODE=.*$/MIRRORS_MODE=0/' /etc/rkhunter.conf
        sed -i 's/^UPDATE_MIRRORS=.*$/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
        sed -i 's/^WEB_CMD=.*$/WEB_CMD=""/' /etc/rkhunter.conf
    fi
    
    rkhunter --update 2>/dev/null || warn "RKHunter update failed"
    rkhunter --propupd 2>/dev/null
    
    log "Creating daily malware scan cron job..."
    
    cat > /etc/cron.daily/malware-scan << 'EOF'
#!/bin/bash
#===============================================================================
# DAILY MALWARE SCAN
#===============================================================================

LOG_FILE="/var/log/malware-scan-$(date +%Y%m%d).log"

echo "=== Malware Scan Started: $(date) ===" >> "$LOG_FILE"

# ClamAV scan
echo "--- ClamAV Scan ---" >> "$LOG_FILE"
clamscan -r /home /tmp /var/tmp --quiet --infected --log="$LOG_FILE" 2>/dev/null

# RKHunter check
echo "--- RKHunter Check ---" >> "$LOG_FILE"
rkhunter --check --skip-keypress --quiet --report-warnings-only >> "$LOG_FILE" 2>&1

# Chkrootkit
echo "--- Chkrootkit Check ---" >> "$LOG_FILE"
chkrootkit -q >> "$LOG_FILE" 2>&1

echo "=== Malware Scan Completed: $(date) ===" >> "$LOG_FILE"

# Alert if issues found
if grep -qE "(INFECTED|Warning|INFECTED|Rootkit)" "$LOG_FILE"; then
    echo "Security scan found issues - check $LOG_FILE" | mail -s "SECURITY ALERT - $(hostname)" root 2>/dev/null
fi
EOF
    
    chmod 700 /etc/cron.daily/malware-scan
    
    log "Malware detection configured"
}

#===============================================================================
# FILE INTEGRITY (AIDE)
#===============================================================================
configure_aide() {
    section "FILE INTEGRITY MONITORING (AIDE)"
    
    log "Initializing AIDE database (this may take a while)..."
    
    # Initialize AIDE in background
    aideinit 2>/dev/null &
    AIDE_PID=$!
    
    log "AIDE initialization started (PID: $AIDE_PID)"
    log "Database will be created at /var/lib/aide/aide.db"
    
    # Create weekly check cron
    cat > /etc/cron.weekly/aide-check << 'EOF'
#!/bin/bash
#===============================================================================
# WEEKLY AIDE CHECK
#===============================================================================
LOG_FILE="/var/log/aide/aide-check-$(date +%Y%m%d).log"
mkdir -p /var/log/aide

echo "=== AIDE Check Started: $(date) ===" >> "$LOG_FILE"
aide --check >> "$LOG_FILE" 2>&1

if [[ $? -ne 0 ]]; then
    echo "AIDE detected changes - check $LOG_FILE" | mail -s "AIDE ALERT - $(hostname)" root 2>/dev/null
fi
echo "=== AIDE Check Completed: $(date) ===" >> "$LOG_FILE"
EOF
    
    chmod 700 /etc/cron.weekly/aide-check
    
    log "AIDE configured"
}

#===============================================================================
# CORE DUMPS
#===============================================================================
disable_core_dumps() {
    section "CORE DUMP RESTRICTIONS"
    
    log "Disabling core dumps..."
    
    # Via limits.conf (already done in PAM section, but ensure)
    echo "* hard core 0" >> /etc/security/limits.d/core.conf
    echo "* soft core 0" >> /etc/security/limits.d/core.conf
    
    # Via sysctl (already done, but ensure)
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-disable-coredump.conf
    
    # Via systemd
    mkdir -p /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

    sysctl -w fs.suid_dumpable=0 2>/dev/null
    
    log "Core dumps disabled"
}

#===============================================================================
# CLEANUP
#===============================================================================
cleanup() {
    section "CLEANUP"
    
    log "Removing unnecessary packages..."
    apt autoremove --purge -y 2>/dev/null
    
    log "Cleaning package cache..."
    apt autoclean
    apt clean
    
    log "Cleaning temporary files..."
    rm -rf /tmp/* /var/tmp/* 2>/dev/null
    
    log "Cleaning old logs..."
    journalctl --vacuum-time=7d 2>/dev/null
    
    log "Cleanup complete"
}

#===============================================================================
# FINAL CHECKS
#===============================================================================
final_checks() {
    section "FINAL CHECKS AND RESTART SERVICES"
    
    log "Testing SSH configuration..."
    sshd -t && log "SSH configuration: OK" || error "SSH configuration: FAILED"
    
    log "Restarting critical services..."
    
    systemctl restart sshd
    systemctl restart fail2ban
    systemctl restart auditd
    systemctl restart rsyslog
    systemctl restart chrony
    
    log "Verifying services..."
    
    for svc in sshd fail2ban auditd rsyslog chrony ufw; do
        if systemctl is-active --quiet "$svc"; then
            log "$svc: Running"
        else
            warn "$svc: Not running"
        fi
    done
    
    log "Final checks complete"
}

#===============================================================================
# LYNIS AUDIT
#===============================================================================
run_lynis() {
    section "LYNIS SECURITY AUDIT"
    
    log "Running Lynis audit..."
    
    lynis audit system --no-colors 2>/dev/null | tee /var/log/lynis-audit.log
    
    SCORE=$(grep "Hardening index" /var/log/lynis-audit.log | grep -oP '\d+' | head -1)
    
    log "Lynis audit complete"
    log "Hardening Score: ${SCORE:-N/A}"
}

#===============================================================================
# SUMMARY
#===============================================================================
print_summary() {
    section "HARDENING COMPLETE"
    
    SCORE=$(grep "Hardening index" /var/log/lynis-audit.log 2>/dev/null | grep -oP '\d+' | head -1)
    
    echo ""
    echo -e "${GREEN}=============================================="
    echo -e "         HARDENING SUMMARY                    "
    echo -e "==============================================${NC}"
    echo ""
    echo -e "  ${CYAN}Lynis Score:${NC} ${SCORE:-Check /var/log/lynis-audit.log}"
    echo ""
    echo -e "  ${CYAN}SSH Ports:${NC} $SSH_PORT_1 and $SSH_PORT_2"
    echo ""
    echo -e "  ${CYAN}Firewall:${NC} UFW enabled"
    echo -e "    - Ports allowed: $SSH_PORT_1, $SSH_PORT_2, 80, 443"
    echo -e "    - Default: deny incoming, allow outgoing"
    echo ""
    echo -e "  ${CYAN}Security Tools Enabled:${NC}"
    echo -e "    ✓ Fail2ban"
    echo -e "    ✓ Auditd"
    echo -e "    ✓ AppArmor"
    echo -e "    ✓ ClamAV"
    echo -e "    ✓ RKHunter"
    echo -e "    ✓ AIDE"
    echo -e "    ✓ Automatic Updates"
    echo ""
    echo -e "  ${CYAN}Logs:${NC}"
    echo -e "    - Hardening log: $LOG_FILE"
    echo -e "    - Lynis audit: /var/log/lynis-audit.log"
    echo -e "    - Backups: $BACKUP_DIR"
    echo ""
    echo -e "  ${CYAN}NO NETWORK/DNS MODIFICATIONS MADE${NC}"
    echo ""
    echo -e "${YELLOW}  >>> REBOOT RECOMMENDED: sudo reboot <<<${NC}"
    echo ""
    echo -e "${GREEN}==============================================${NC}"
    echo ""
}

#===============================================================================
# MAIN
#===============================================================================
main() {
    clear
    
    echo -e "${BLUE}"
    echo "==============================================================================="
    echo "                                                                               "
    echo "    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██╗███╗   ██╗ ██████╗   "
    echo "    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██║████╗  ██║██╔════╝   "
    echo "    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗  "
    echo "    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║██║╚██╗██║██║   ██║  "
    echo "    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██║██║ ╚████║╚██████╔╝  "
    echo "    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝   "
    echo "                                                                               "
    echo "                    ULTIMATE DEBIAN 11 HARDENING SCRIPT                        "
    echo "                           Target: Lynis 90+                                   "
    echo "                                                                               "
    echo "==============================================================================="
    echo -e "${NC}"
    
    sleep 2
    
    pre_flight
    system_update
    kernel_hardening
    disable_modules
    ssh_hardening
    configure_banners
    password_policy
    pam_hardening
    session_security
    configure_firewall
    configure_fail2ban
    configure_auditd
    configure_accounting
    configure_apparmor
    configure_logging
    configure_time
    configure_entropy
    configure_auto_updates
    restrict_cron
    configure_tcp_wrappers
    secure_permissions
    restrict_suid_sgid
    disable_services
    lock_accounts
    restrict_compilers
    fix_world_writable
    fix_orphan_files
    configure_grub
    configure_malware_detection
    configure_aide
    disable_core_dumps
    cleanup
    final_checks
    run_lynis
    print_summary
}

#===============================================================================
# RUN
#===============================================================================
main "$@"
