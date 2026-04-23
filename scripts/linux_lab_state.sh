#!/usr/bin/env bash
set -euo pipefail

# Lab fixture helper for YMC-L scanner validation.
#
# This script is intentionally not a production hardening or remediation tool.
# Use it only on disposable lab VMs after taking a hypervisor snapshot.

MODE="${1:-}"
BACKUP_DIR="/var/tmp/ymc-l-lab-state-backup"
SSHD_DROPIN="/etc/ssh/sshd_config.d/01-ymc-l-lab.conf"
LEGACY_SSHD_DROPIN="/etc/ssh/sshd_config.d/99-ymc-l-lab.conf"
SYSCTL_DROPIN="/etc/sysctl.d/99-ymc-l-lab.conf"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/99-ymc-l-lab.conf"
FINDING_DIR="/tmp/ymc-l-world-writable-no-sticky"

usage() {
  cat <<'USAGE'
Usage:
  sudo scripts/linux_lab_state.sh pass
  sudo scripts/linux_lab_state.sh fail
  sudo scripts/linux_lab_state.sh restore
  sudo scripts/linux_lab_state.sh status

Modes:
  pass      Apply conservative settings expected to satisfy several YMC-L checks.
  fail      Apply controlled weak settings expected to trigger several findings.
  restore   Restore files backed up by this script and remove lab artifacts.
  status    Print current relevant settings.

Take a VM snapshot before running this. Do not use on production systems.
USAGE
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run with sudo or as root." >&2
    exit 2
  fi
}

backup_once() {
  local path="$1"
  local backup_path="$BACKUP_DIR/${path#/}"
  mkdir -p "$(dirname "$backup_path")"
  if [[ -e "$path" && ! -e "$backup_path" ]]; then
    cp -a "$path" "$backup_path"
  fi
}

backup_missing_marker() {
  local path="$1"
  local marker="$BACKUP_DIR/${path#/}.missing"
  if [[ ! -e "$path" && ! -e "$marker" ]]; then
    mkdir -p "$(dirname "$marker")"
    : >"$marker"
  fi
}

write_file() {
  local path="$1"
  backup_once "$path"
  backup_missing_marker "$path"
  mkdir -p "$(dirname "$path")"
  cat >"$path"
}

restore_path() {
  local path="$1"
  local backup_path="$BACKUP_DIR/${path#/}"
  local marker="$BACKUP_DIR/${path#/}.missing"
  if [[ -e "$backup_path" ]]; then
    mkdir -p "$(dirname "$path")"
    cp -a "$backup_path" "$path"
  elif [[ -e "$marker" ]]; then
    rm -f "$path"
  fi
}

reload_services() {
  sysctl --system >/dev/null || true
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    systemctl restart systemd-journald 2>/dev/null || true
  fi
}

apply_pass() {
  require_root
  mkdir -p "$BACKUP_DIR"
  write_file "$SSHD_DROPIN" <<'EOF'
# YMC-L lab pass-state fixture. Remove with linux_lab_state.sh restore.
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
EOF
  rm -f "$LEGACY_SSHD_DROPIN"
  write_file "$SYSCTL_DROPIN" <<'EOF'
# YMC-L lab pass-state fixture. Remove with linux_lab_state.sh restore.
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
EOF
  write_file "$JOURNALD_DROPIN" <<'EOF'
# YMC-L lab pass-state fixture. Remove with linux_lab_state.sh restore.
[Journal]
Storage=persistent
EOF
  rm -rf "$FINDING_DIR"
  reload_services
  echo "Applied YMC-L pass-state lab fixture."
}

apply_fail() {
  require_root
  mkdir -p "$BACKUP_DIR"
  write_file "$SSHD_DROPIN" <<'EOF'
# YMC-L lab fail-state fixture. Remove with linux_lab_state.sh restore.
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
X11Forwarding yes
MaxAuthTries 10
EOF
  rm -f "$LEGACY_SSHD_DROPIN"
  write_file "$SYSCTL_DROPIN" <<'EOF'
# YMC-L lab fail-state fixture. Remove with linux_lab_state.sh restore.
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.tcp_syncookies = 0
kernel.dmesg_restrict = 0
kernel.randomize_va_space = 0
fs.suid_dumpable = 1
EOF
  write_file "$JOURNALD_DROPIN" <<'EOF'
# YMC-L lab fail-state fixture. Remove with linux_lab_state.sh restore.
[Journal]
Storage=volatile
EOF
  mkdir -p "$FINDING_DIR"
  chmod 0777 "$FINDING_DIR"
  reload_services
  echo "Applied YMC-L fail-state lab fixture."
}

restore_state() {
  require_root
  restore_path "$SSHD_DROPIN"
  restore_path "$LEGACY_SSHD_DROPIN"
  restore_path "$SYSCTL_DROPIN"
  restore_path "$JOURNALD_DROPIN"
  rm -rf "$FINDING_DIR"
  reload_services
  echo "Restored YMC-L lab fixture changes where backups existed."
}

show_status() {
  echo "== sshd effective values =="
  if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | grep -Ei \
      '^(permitrootlogin|passwordauthentication|permitemptypasswords|'\
'x11forwarding|maxauthtries) ' \
      || true
  else
    echo "sshd unavailable"
  fi
  echo
  echo "== sysctl values =="
  for key in \
    net.ipv4.ip_forward \
    net.ipv6.conf.all.forwarding \
    net.ipv4.conf.all.accept_redirects \
    net.ipv4.conf.all.send_redirects \
    net.ipv4.conf.all.accept_source_route \
    net.ipv4.tcp_syncookies \
    kernel.dmesg_restrict \
    kernel.randomize_va_space \
    fs.suid_dumpable
  do
    sysctl -n "$key" 2>/dev/null | awk -v key="$key" '{print key "=" $1}' || true
  done
  echo
  echo "== fixture artifacts =="
  ls -ld "$FINDING_DIR" 2>/dev/null || echo "$FINDING_DIR absent"
}

case "$MODE" in
  pass) apply_pass ;;
  fail) apply_fail ;;
  restore) restore_state ;;
  status) show_status ;;
  ""|-h|--help|help) usage ;;
  *)
    usage
    exit 2
    ;;
esac
