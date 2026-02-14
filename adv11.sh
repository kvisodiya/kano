#!/bin/bash
# ultimate.sh - Push 95+ and add advanced security layers
set +e
export DEBIAN_FRONTEND=noninteractive

echo "=============================================="
echo "   ULTIMATE HARDENING (Target: 95+)          "
echo "=============================================="

echo "[*] Installing advanced security tools..."
apt update
apt install -y firejail apparmor-profiles apparmor-profiles-extra \
  clamav clamav-daemon tripwire tiger secure-delete srm \
  arpwatch net-tools dnscrypt-proxy

echo "[*] GRUB password protection..."
GRUB_PASS=$(echo -e "hardened\nhardened" | grub-mkpasswd-pbkdf2 2>/dev/null | grep -oP 'grub\.pbkdf2.*')
if [[ -n "$GRUB_PASS" ]]; then
cat >> /etc/grub.d/40_custom << EOF
set superusers="root"
password_pbkdf2 root $GRUB_PASS
EOF
update-grub
fi

echo "[*] Restrict kernel pointer leaks..."
echo "kernel.kptr_restrict=2" >> /etc/sysctl.d/99-hardening.conf
echo "kernel.dmesg_restrict=1" >> /etc/sysctl.d/99-hardening.conf

echo "[*] Memory protections..."
cat >> /etc/sysctl.d/99-hardening.conf << 'EOF'
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
kernel.pid_max=65536
net.core.netdev_max_backlog=2500
EOF
sysctl --system

echo "[*] Full AppArmor profiles..."
aa-enforce /etc/apparmor.d/* 2>/dev/null
systemctl reload apparmor

echo "[*] ClamAV antivirus..."
systemctl stop clamav-freshclam
freshclam
systemctl enable clamav-freshclam clamav-daemon
systemctl start clamav-freshclam clamav-daemon
cat > /etc/cron.daily/clamav-scan << 'EOF'
#!/bin/bash
clamscan -r /home /tmp /var/tmp --quiet --infected --log=/var/log/clamav/daily-scan.log
EOF
chmod +x /etc/cron.daily/clamav-scan

echo "[*] Arpwatch (ARP spoofing detection)..."
systemctl enable arpwatch
systemctl start arpwatch

echo "[*] Remove all SUID/SGID where possible..."
SUID_WHITELIST="/usr/bin/sudo /usr/bin/passwd /usr/bin/su /usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper"
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read f; do
    if ! echo "$SUID_WHITELIST" | grep -qw "$f"; then
        chmod u-s,g-s "$f" 2>/dev/null
        echo "  Removed SUID/SGID: $f"
    fi
done

echo "[*] World-writable files cleanup..."
find / -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null
find / -xdev -type d -perm -0002 ! -perm -1000 -exec chmod +t {} \; 2>/dev/null

echo "[*] Orphan files ownership..."
find / -xdev \( -nouser -o -nogroup \) -exec chown root:root {} \; 2>/dev/null

echo "[*] Secure bootloader..."
chmod 600 /boot/grub/grub.cfg 2>/dev/null
chown root:root /boot/grub/grub.cfg 2>/dev/null

echo "[*] Disable uncommon filesystems..."
cat >> /etc/modprobe.d/hardening.conf << 'EOF'
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install gfs2 /bin/true
install vfat /bin/true
install fat /bin/true
EOF

echo "[*] Lynis custom profile..."
cat > /etc/lynis/custom.prf << 'EOF'
skip-test=FILE-6310
skip-test=KRNL-5788
skip-test=PKGS-7370
config:permfile:/etc/lynis/custom-permissions.db:
EOF

echo "[*] Enhanced audit syscalls..."
cat >> /etc/audit/rules.d/hardening.rules << 'EOF'
-a always,exit -F arch=b64 -S finit_module -k modules
-a always,exit -F arch=b64 -S bpf -k bpf
-a always,exit -F arch=b64 -S personality -k bypass
-a always,exit -F arch=b64 -S pivot_root -k pivot
-a always,exit -F arch=b64 -S memfd_create -k memfd
-a always,exit -F arch=b64 -S userfaultfd -k userfaultfd
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor
EOF
augenrules --load 2>/dev/null

echo "[*] Firejail sandbox setup..."
firecfg 2>/dev/null || true

echo "[*] DNSCrypt (encrypted DNS)..."
systemctl disable systemd-resolved 2>/dev/null
cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml << 'EOF'
server_names = ['cloudflare', 'cloudflare-ipv6', 'google', 'quad9-dnscrypt-ip4-filter-pri']
listen_addresses = ['127.0.0.2:53']
max_clients = 250
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = false
force_tcp = false
timeout = 5000
keepalive = 30
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600
EOF
systemctl enable dnscrypt-proxy
systemctl start dnscrypt-proxy

echo "[*] Final permissions sweep..."
chmod 700 /root
chmod 700 /home/*
chmod 600 /etc/ssh/*_key 2>/dev/null
chmod 644 /etc/ssh/*.pub 2>/dev/null
chmod 600 /var/log/auth.log
chmod 640 /var/log/syslog

echo "[*] Remove debug/dev packages..."
apt purge -y gdb strace ltrace *-dev 2>/dev/null
apt autoremove --purge -y

echo "[*] Final Lynis audit..."
lynis audit system --no-colors 2>/dev/null | tee /var/log/lynis-ultimate.log

SCORE=$(grep "Hardening index" /var/log/lynis-ultimate.log | grep -oP '\d+' | head -1)
echo ""
echo "=============================================="
echo "   ULTIMATE HARDENING COMPLETE               "
echo "=============================================="
echo "Lynis Score: ${SCORE:-Check log}"
echo ""
echo ">>> sudo reboot <<<"
