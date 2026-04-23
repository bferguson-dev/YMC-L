"""Programmatically checkable Linux SSH control catalog."""

from __future__ import annotations

import re

from checks.linux.common import (
    STATUS_ERROR,
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_WARNING,
    CommandCheckSpec,
    bool_setting,
    int_setting,
    register_command_check,
    str_list_setting,
)


def pass_if_exit_zero(ok: str, fail: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        if exit_code == 0:
            return STATUS_PASS, ok, "", None
        return STATUS_FAIL, fail, "", {"exit_code": exit_code}

    return evaluate


def warning_inventory(finding: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        status = STATUS_WARNING if raw else STATUS_ERROR
        return status, finding if raw else "No evidence returned.", "", None

    return evaluate


def pass_contains(token: str, ok: str, fail: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        if token.lower() in raw.lower():
            return STATUS_PASS, ok, "", None
        return STATUS_FAIL, fail, "", None

    return evaluate


def pass_line_equals(token: str, ok: str, fail: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        if any(line.strip().lower() == token.lower() for line in raw.splitlines()):
            return STATUS_PASS, ok, "", None
        return STATUS_FAIL, fail, "", None

    return evaluate


def fail_line_equals(token: str, ok: str, fail: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        if any(line.strip().lower() == token.lower() for line in raw.splitlines()):
            return STATUS_FAIL, fail, "", None
        return STATUS_PASS, ok, "", None

    return evaluate


def fail_contains(token: str, ok: str, fail: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        if token.lower() in raw.lower():
            return STATUS_FAIL, fail, "", None
        return STATUS_PASS, ok, "", None

    return evaluate


def reboot_required_evaluator(raw: str, exit_code: int, settings: dict):
    if raw.strip() == "no-reboot-required":
        return STATUS_PASS, "No reboot-required flag was found.", "", None
    if "reboot-required" in raw:
        return STATUS_FAIL, "The host reports that a reboot is required.", "", None
    return STATUS_WARNING, "Reboot-required state could not be determined.", "", None


def pass_value(name: str, expected: str):
    pattern = re.compile(rf"^{re.escape(name)}=(.*)$", re.MULTILINE)

    def evaluate(raw: str, exit_code: int, settings: dict):
        match = pattern.search(raw)
        if "sshd-unavailable" in raw.lower():
            return (
                STATUS_WARNING,
                f"{name} could not be checked without sshd -T.",
                "",
                None,
            )
        if not match:
            return STATUS_ERROR, f"{name} was not returned by the target.", "", None
        value = match.group(1).strip()
        if value == expected:
            return STATUS_PASS, f"{name} is set to {expected}.", "", {"value": value}
        return (
            STATUS_FAIL,
            f"{name} is set to {value}, expected {expected}.",
            "",
            {
                "value": value,
            },
        )

    return evaluate


def pass_value_in(
    name: str,
    allowed_values: set[str],
    setting_key: str | None = None,
):
    pattern = re.compile(rf"^{re.escape(name)}=(.*)$", re.MULTILINE)

    def evaluate(raw: str, exit_code: int, settings: dict):
        configured = allowed_values
        if setting_key:
            configured = set(
                str_list_setting(settings, setting_key, sorted(allowed_values))
            )
        match = pattern.search(raw)
        if not match:
            return STATUS_ERROR, f"{name} was not returned by the target.", "", None
        value = match.group(1).strip()
        if value in configured:
            return STATUS_PASS, f"{name} is set to {value}.", "", {"value": value}
        expected = ", ".join(sorted(configured))
        return (
            STATUS_FAIL,
            f"{name} is set to {value}, expected one of {expected}.",
            "",
            {
                "value": value,
                "expected_values": sorted(configured),
            },
        )

    return evaluate


def pass_int_max(name: str, max_key: str, default: int, unit: str = ""):
    pattern = re.compile(rf"^{re.escape(name)}=(\d+)$", re.MULTILINE)

    def evaluate(raw: str, exit_code: int, settings: dict):
        threshold = int_setting(settings, max_key, default)
        if "sshd-unavailable" in raw.lower():
            return (
                STATUS_WARNING,
                f"{name} could not be checked without sshd -T.",
                "",
                None,
            )
        match = pattern.search(raw)
        if not match:
            return STATUS_ERROR, f"{name} was not returned by the target.", "", None
        value = int(match.group(1))
        suffix = f" {unit}" if unit else ""
        if value <= threshold:
            return (
                STATUS_PASS,
                f"{name} is {value}{suffix}, within {threshold}.",
                "",
                {
                    "value": value,
                    "threshold": threshold,
                },
            )
        return (
            STATUS_FAIL,
            f"{name} is {value}{suffix}, above {threshold}.",
            "",
            {
                "value": value,
                "threshold": threshold,
            },
        )

    return evaluate


def pass_int_min(name: str, min_key: str, default: int, unit: str = ""):
    pattern = re.compile(rf"^{re.escape(name)}=(\d+)$", re.MULTILINE)

    def evaluate(raw: str, exit_code: int, settings: dict):
        threshold = int_setting(settings, min_key, default)
        match = pattern.search(raw)
        if not match:
            return STATUS_ERROR, f"{name} was not returned by the target.", "", None
        value = int(match.group(1))
        suffix = f" {unit}" if unit else ""
        if value >= threshold:
            return (
                STATUS_PASS,
                f"{name} is {value}{suffix}, at least {threshold}.",
                "",
                {
                    "value": value,
                    "threshold": threshold,
                },
            )
        return (
            STATUS_FAIL,
            f"{name} is {value}{suffix}, below {threshold}.",
            "",
            {
                "value": value,
                "threshold": threshold,
            },
        )

    return evaluate


def pass_int_between(
    name: str,
    min_value: int,
    max_key: str,
    default_max: int,
    unit: str = "",
):
    pattern = re.compile(rf"^{re.escape(name)}=(\d+)$", re.MULTILINE)

    def evaluate(raw: str, exit_code: int, settings: dict):
        threshold = int_setting(settings, max_key, default_max)
        if "sshd-unavailable" in raw.lower():
            return (
                STATUS_WARNING,
                f"{name} could not be checked without sshd -T.",
                "",
                None,
            )
        match = pattern.search(raw)
        if not match:
            return STATUS_ERROR, f"{name} was not returned by the target.", "", None
        value = int(match.group(1))
        suffix = f" {unit}" if unit else ""
        if min_value <= value <= threshold:
            return (
                STATUS_PASS,
                f"{name} is {value}{suffix}, within policy.",
                "",
                {
                    "value": value,
                    "min": min_value,
                    "threshold": threshold,
                },
            )
        return (
            STATUS_FAIL,
            f"{name} is {value}{suffix}, outside policy.",
            "",
            {
                "value": value,
                "min": min_value,
                "threshold": threshold,
            },
        )

    return evaluate


def no_lines(ok: str, fail: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        if "permission-denied:" in raw:
            return (
                STATUS_WARNING,
                "Required evidence could not be read with current account permissions.",
                "",
                {"permission_denied": raw.strip()},
            )
        lines = [line for line in raw.splitlines() if line.strip()]
        if not lines:
            return STATUS_PASS, ok, "", {"count": 0}
        return STATUS_FAIL, f"{fail} Count: {len(lines)}.", "", {"count": len(lines)}

    return evaluate


def any_lines_warning(finding: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        lines = [line for line in raw.splitlines() if line.strip()]
        if not lines:
            return STATUS_PASS, "No matching review items found.", "", {"count": 0}
        return (
            STATUS_WARNING,
            f"{finding} Count: {len(lines)}.",
            "",
            {
                "count": len(lines),
            },
        )

    return evaluate


def presence_requirement(
    setting_key: str,
    found_message: str,
    missing_message: str,
):
    def evaluate(raw: str, exit_code: int, settings: dict):
        required = bool_setting(settings, setting_key, False)
        lines = [line for line in raw.splitlines() if line.strip()]
        if lines:
            if required:
                return STATUS_PASS, found_message, "", {"count": len(lines)}
            return STATUS_WARNING, found_message, "", {"count": len(lines)}
        if required:
            return STATUS_FAIL, missing_message, "", {"count": 0}
        return STATUS_WARNING, missing_message, "", {"count": 0}

    return evaluate


def service_active(service_name: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        if "not-installed" in raw:
            return STATUS_FAIL, f"{service_name} is not installed.", "", None
        if any(line.strip() == "active" for line in raw.splitlines()):
            return STATUS_PASS, f"{service_name} is active.", "", None
        return STATUS_FAIL, f"{service_name} is not active. Evidence: {raw}", "", None

    return evaluate


def sshd_effective_value(
    name: str, pass_values: set[str], fail_if_missing: bool = True
):
    pattern = re.compile(rf"^{re.escape(name.lower())}\s+(.+)$", re.MULTILINE)

    def evaluate(raw: str, exit_code: int, settings: dict):
        lowered = raw.lower()
        if "sshd-unavailable" in lowered:
            return (
                STATUS_WARNING,
                "sshd -T was not available or could not parse effective config.",
                "",
                None,
            )
        match = pattern.search(lowered)
        if not match:
            return STATUS_ERROR, f"Effective sshd value {name} was not found.", "", None
        value = match.group(1).strip()
        if value in pass_values:
            return STATUS_PASS, f"sshd {name} is {value}.", "", {"value": value}
        return STATUS_FAIL, f"sshd {name} is {value}.", "", {"value": value}

    return evaluate


def firewall_evaluator(raw: str, exit_code: int, settings: dict):
    lowered = raw.lower()
    if "ufw=active" in lowered or "firewalld=active" in lowered:
        return STATUS_PASS, "A host firewall service is active.", "", None
    if "nft_rules=yes" in lowered or "iptables_rules=yes" in lowered:
        return (
            STATUS_WARNING,
            "Firewall rules exist, but no managed service is active.",
            "",
            None,
        )
    return (
        STATUS_FAIL,
        "No active host firewall service or rules were detected.",
        "",
        None,
    )


def security_module_evaluator(raw: str, exit_code: int, settings: dict):
    lowered = raw.lower()
    if "selinux=enforcing" in lowered or "apparmor=enabled" in lowered:
        return STATUS_PASS, "SELinux or AppArmor appears enabled.", "", None
    if "selinux=permissive" in lowered:
        return STATUS_WARNING, "SELinux is permissive. Review host policy.", "", None
    return STATUS_FAIL, "SELinux/AppArmor enforcement was not detected.", "", None


def auto_updates_evaluator(raw: str, exit_code: int, settings: dict):
    lowered = raw.lower()
    markers = [
        "unattended-upgrades=installed",
        "dnf-automatic=installed",
        "yum-cron=installed",
        "zypper=patch-timer",
    ]
    if any(marker in lowered for marker in markers):
        return STATUS_PASS, "Automatic update tooling appears configured.", "", None
    return STATUS_WARNING, "Automatic update tooling was not detected.", "", None


def disk_usage_evaluator(raw: str, exit_code: int, settings: dict):
    threshold = int_setting(settings, "disk_usage_warning_percent", 85)
    offenders = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[4].endswith("%"):
            used = int(parts[4].rstrip("%"))
            if used >= threshold:
                offenders.append(line)
    if offenders:
        return (
            STATUS_WARNING,
            f"One or more filesystems are above {threshold}%.",
            "",
            {
                "offenders": offenders,
            },
        )
    return STATUS_PASS, f"No filesystems are above {threshold}% usage.", "", None


def mount_options_evaluator(raw: str, exit_code: int, settings: dict):
    if not raw.strip():
        return (
            STATUS_WARNING,
            "/tmp, /var/tmp, and /dev/shm were not reported as separate mounts.",
            "",
            None,
        )
    return (
        STATUS_WARNING,
        "Temporary filesystem mount options collected for review.",
        "",
        None,
    )


def package_signing_evaluator(raw: str, exit_code: int, settings: dict):
    lowered = raw.lower()
    if "apt_signed=yes" in lowered or "rpm_gpgcheck=yes" in lowered:
        return (
            STATUS_PASS,
            "Package repository signature checks appear enabled.",
            "",
            None,
        )
    if "unknown" in lowered:
        return (
            STATUS_WARNING,
            "Package manager signature state could not be determined.",
            "",
            None,
        )
    return (
        STATUS_FAIL,
        "Package repository signature checks were not confirmed.",
        "",
        None,
    )


def pass_login_defs_value(
    name: str,
    pass_values: set[str],
    setting_key: str | None = None,
):
    pattern = re.compile(rf"^{re.escape(name)}=(.*)$", re.MULTILINE)

    def evaluate(raw: str, exit_code: int, settings: dict):
        configured = pass_values
        if setting_key:
            configured = set(
                str_list_setting(settings, setting_key, sorted(pass_values))
            )
        match = pattern.search(raw)
        if not match:
            return STATUS_WARNING, f"{name} was not defined for review.", "", None
        value = match.group(1).strip().lower()
        if value in configured:
            return STATUS_PASS, f"{name} is set to {value}.", "", {"value": value}
        return (
            STATUS_FAIL,
            f"{name} is set to {value}.",
            "",
            {
                "value": value,
                "expected_values": sorted(configured),
            },
        )

    return evaluate


def login_defs_int(name: str) -> str:
    return f'awk \'$1 == "{name}" {{print "{name}="$2}}\' /etc/login.defs 2>/dev/null'


def service_absent_or_inactive(service_name: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        if "active" in {line.strip().lower() for line in raw.splitlines()}:
            return STATUS_FAIL, f"{service_name} is active.", "", None
        return STATUS_PASS, f"{service_name} is not active.", "", None

    return evaluate


def module_disabled_evaluator(module_name: str):
    def evaluate(raw: str, exit_code: int, settings: dict):
        lowered = raw.lower()
        if "install /bin/true" in lowered or "install /bin/false" in lowered:
            return STATUS_PASS, f"{module_name} load is disabled.", "", None
        if "blacklist" in lowered:
            return (
                STATUS_WARNING,
                f"{module_name} is blacklisted; verify load policy.",
                "",
                None,
            )
        if "not-found" in lowered or "not-configured" in lowered:
            return (
                STATUS_PASS,
                f"{module_name} is unavailable or not configured.",
                "",
                None,
            )
        return STATUS_FAIL, f"{module_name} does not appear disabled.", "", None

    return evaluate


def module_probe_command(module_name: str) -> str:
    return (
        "MODPROBE=$(command -v modprobe 2>/dev/null || "
        "(test -x /usr/sbin/modprobe && echo /usr/sbin/modprobe) || true); "
        'test -n "$MODPROBE" || { echo modprobe-not-found; exit 0; }; '
        f"$MODPROBE -n -v {module_name} 2>/dev/null || echo not-configured; "
        f'grep -Rhs "^blacklist[[:space:]]\\+{module_name}$" '
        "/etc/modprobe.d 2>/dev/null || true"
    )


SSHD_T = (
    "SSHD=$(command -v sshd 2>/dev/null || "
    "(test -x /usr/sbin/sshd && echo /usr/sbin/sshd) || true); "
    'if test -n "$SSHD"; then "$SSHD" -T 2>/dev/null || echo sshd-unavailable; '
    "else echo sshd-unavailable; fi"
)


def sshd_t_filter(filter_command: str) -> str:
    return f"{SSHD_T} | {filter_command}"


def shadow_read_command(awk_program: str) -> str:
    return (
        "test -r /etc/shadow || { echo permission-denied:/etc/shadow; "
        "exit 0; }; "
        f"awk -F: '{awk_program}' /etc/shadow"
    )


CHECKS = [
    CommandCheckSpec(
        "SB-001",
        "Linux OS Release Inventory",
        "System Baseline",
        "Collect OS release and kernel evidence.",
        "test -f /etc/os-release && cat /etc/os-release; uname -a",
        "",
        warning_inventory("OS release and kernel inventory collected."),
    ),
    CommandCheckSpec(
        "SB-002",
        "Package Manager Detection",
        "System Baseline",
        "Detect the package manager available on the host.",
        "for c in apt-get dnf yum zypper apk; do "
        "command -v $c >/dev/null 2>&1 && echo $c; done",
        "",
        warning_inventory("Package manager inventory collected."),
    ),
    CommandCheckSpec(
        "SB-003",
        "Time Synchronization Service",
        "System Baseline",
        "Verify a time synchronization service is active.",
        "for s in chronyd systemd-timesyncd ntpd; do "
        "systemctl is-active $s 2>/dev/null && echo active && exit 0; "
        "done; echo inactive",
        "Enable chrony, systemd-timesyncd, or ntpd and point it at approved sources.",
        pass_line_equals(
            "active",
            "A time synchronization service is active.",
            "No active time synchronization service was detected.",
        ),
    ),
    CommandCheckSpec(
        "SB-004",
        "Reboot Required Signal",
        "System Baseline",
        "Detect whether the host reports a pending reboot.",
        "if test -f /var/run/reboot-required; then cat /var/run/reboot-required; "
        "else echo no-reboot-required; fi",
        "Schedule a maintenance reboot if patching or kernel updates require it.",
        reboot_required_evaluator,
    ),
    CommandCheckSpec(
        "AC-001",
        "UID 0 Account Review",
        "Access Control",
        "Ensure no accounts other than root have UID 0.",
        'awk -F: \'$3 == 0 && $1 != "root" {print $1":"$3}\' /etc/passwd',
        "Remove UID 0 from unauthorized accounts; use sudo for delegated privilege.",
        no_lines("No non-root UID 0 accounts found.", "Non-root UID 0 accounts found."),
    ),
    CommandCheckSpec(
        "AC-002",
        "Empty Password Hashes",
        "Access Control",
        "Ensure local accounts do not have empty password hashes.",
        shadow_read_command('($2 == "") {print $1}'),
        "Lock or set passwords for accounts with empty shadow password fields.",
        no_lines(
            "No empty password hashes found.", "Accounts with empty passwords found."
        ),
    ),
    CommandCheckSpec(
        "AC-003",
        "Root Account Lock State",
        "Access Control",
        "Verify root account password authentication is locked or disabled.",
        shadow_read_command('$1 == "root" {print $2}'),
        "Lock root password auth with passwd -l root and use sudo for privilege.",
        lambda raw, exit_code, settings: (
            (
                STATUS_WARNING,
                "Root shadow entry could not be read with current account permissions.",
                "",
                None,
            )
            if "permission-denied:" in raw
            else (
                STATUS_WARNING,
                "Root password hash was not returned for review.",
                "",
                None,
            )
            if not raw.strip()
            else (STATUS_PASS, "Root password hash is locked/disabled.", "", None)
            if raw.startswith(("!", "*"))
            else (
                STATUS_WARNING,
                "Root password hash appears active. Review policy.",
                "",
                None,
            )
        ),
    ),
    CommandCheckSpec(
        "AC-004",
        "Sudoers Syntax",
        "Access Control",
        "Validate sudoers syntax when visudo is present.",
        "VISUDO=$(command -v visudo 2>/dev/null || "
        "(test -x /usr/sbin/visudo && echo /usr/sbin/visudo) || true); "
        'test -n "$VISUDO" && "$VISUDO" -c 2>&1 || echo visudo-unavailable',
        "Fix sudoers syntax with visudo before relying on sudo policy.",
        lambda raw, exit_code, settings: (
            (
                STATUS_WARNING,
                "visudo is unavailable; sudoers syntax was not checked.",
                "",
                None,
            )
            if "visudo-unavailable" in raw
            else (STATUS_PASS, "sudoers syntax validation passed.", "", None)
            if "parsed OK" in raw or "files parsed OK" in raw
            else (STATUS_FAIL, "sudoers syntax validation did not pass.", "", None)
        ),
    ),
    CommandCheckSpec(
        "AC-005",
        "Passwordless Sudo Entries",
        "Access Control",
        "Identify NOPASSWD sudo entries for least-privilege review.",
        "grep -RIn --exclude='*.dpkg-*' 'NOPASSWD' "
        "/etc/sudoers /etc/sudoers.d 2>/dev/null",
        "Remove NOPASSWD entries unless there is a documented exception.",
        no_lines("No NOPASSWD sudo entries found.", "NOPASSWD sudo entries found."),
    ),
    CommandCheckSpec(
        "AC-006",
        "Interactive Shell Users",
        "Access Control",
        "Enumerate accounts with interactive shells.",
        "awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ "
        '{print $1":"$7}\' /etc/passwd',
        "Review interactive shell users and remove access where not required.",
        any_lines_warning("Interactive shell users require review."),
    ),
    CommandCheckSpec(
        "AC-007",
        "Sensitive Account File Permissions",
        "Access Control",
        "Verify key account database permissions.",
        "stat -c '%a %U %G %n' /etc/passwd /etc/shadow "
        "/etc/group /etc/gshadow 2>/dev/null",
        "Set ownership to root and restrictive modes for passwd/shadow/group files.",
        lambda raw, exit_code, settings: (
            (
                STATUS_FAIL,
                "Sensitive account file permissions require review.",
                "",
                None,
            )
            if any(
                line.split()[0] not in {"644", "640", "600", "400", "000", "0"}
                for line in raw.splitlines()
                if line.strip()
            )
            else (
                STATUS_PASS,
                "Sensitive account file permissions look restrictive.",
                "",
                None,
            )
        ),
    ),
    CommandCheckSpec(
        "AC-008",
        "Password Maximum Age Policy",
        "Access Control",
        "Verify PASS_MAX_DAYS is within the configured threshold.",
        'awk \'$1 == "PASS_MAX_DAYS" {print "PASS_MAX_DAYS="$2}\' /etc/login.defs',
        "Set PASS_MAX_DAYS in /etc/login.defs to the organization threshold.",
        pass_int_max("PASS_MAX_DAYS", "max_password_age_days", 90, "days"),
    ),
    CommandCheckSpec(
        "AC-009",
        "Password Minimum Age Policy",
        "Access Control",
        "Verify PASS_MIN_DAYS meets the configured threshold.",
        login_defs_int("PASS_MIN_DAYS"),
        "Set PASS_MIN_DAYS in /etc/login.defs to reduce rapid password cycling.",
        pass_int_min("PASS_MIN_DAYS", "min_password_age_days", 1, "days"),
    ),
    CommandCheckSpec(
        "AC-010",
        "Password Warning Age Policy",
        "Access Control",
        "Verify PASS_WARN_AGE meets the configured threshold.",
        login_defs_int("PASS_WARN_AGE"),
        "Set PASS_WARN_AGE in /etc/login.defs to warn users before expiration.",
        pass_int_min("PASS_WARN_AGE", "password_warn_age_days", 7, "days"),
    ),
    CommandCheckSpec(
        "AC-011",
        "Password Hashing Algorithm",
        "Access Control",
        "Verify login.defs uses a modern password hashing method.",
        'awk \'$1 == "ENCRYPT_METHOD" {print "ENCRYPT_METHOD="$2}\' /etc/login.defs',
        "Set ENCRYPT_METHOD to yescrypt or SHA512 where supported.",
        pass_login_defs_value(
            "ENCRYPT_METHOD",
            {"yescrypt", "sha512"},
            "encrypt_method_allowed_values",
        ),
    ),
    CommandCheckSpec(
        "AC-012",
        "Default Login UMASK",
        "Access Control",
        "Verify login.defs UMASK is restrictive.",
        'awk \'$1 == "UMASK" {print "UMASK="$2}\' /etc/login.defs',
        "Set UMASK to 027 or more restrictive in /etc/login.defs.",
        pass_login_defs_value(
            "UMASK",
            {"027", "077"},
            "umask_allowed_values",
        ),
    ),
    CommandCheckSpec(
        "AC-013",
        "Duplicate UIDs",
        "Access Control",
        "Identify duplicate UIDs in local passwd records.",
        "cut -d: -f3 /etc/passwd | sort | uniq -d",
        "Assign unique UIDs to local accounts.",
        no_lines("No duplicate UIDs found.", "Duplicate UIDs found."),
    ),
    CommandCheckSpec(
        "AC-014",
        "Duplicate GIDs",
        "Access Control",
        "Identify duplicate GIDs in local group records.",
        "cut -d: -f3 /etc/group | sort | uniq -d",
        "Assign unique GIDs to local groups.",
        no_lines("No duplicate GIDs found.", "Duplicate GIDs found."),
    ),
    CommandCheckSpec(
        "AC-015",
        "Duplicate User Names",
        "Access Control",
        "Identify duplicate local user names.",
        "cut -d: -f1 /etc/passwd | sort | uniq -d",
        "Remove or rename duplicate local user records.",
        no_lines("No duplicate user names found.", "Duplicate user names found."),
    ),
    CommandCheckSpec(
        "AC-016",
        "Duplicate Group Names",
        "Access Control",
        "Identify duplicate local group names.",
        "cut -d: -f1 /etc/group | sort | uniq -d",
        "Remove or rename duplicate local group records.",
        no_lines("No duplicate group names found.", "Duplicate group names found."),
    ),
    CommandCheckSpec(
        "AC-017",
        "Interactive User Home Directories",
        "Access Control",
        "Verify interactive users have existing home directories.",
        "awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1\":\"$6}' "
        '/etc/passwd | while IFS=: read -r u h; do test -d "$h" || echo "$u:$h"; done',
        "Create, assign, or remove home directories for interactive accounts.",
        no_lines(
            "Interactive users have existing home directories.",
            "Missing home directories found.",
        ),
    ),
    CommandCheckSpec(
        "AC-018",
        "Interactive User Home Ownership",
        "Access Control",
        "Verify interactive user home directories are owned by their users.",
        'awk -F: \'$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1" "$3" "$6}\' '
        '/etc/passwd | while read -r u uid h; do test -d "$h" || continue; '
        'owner=$(stat -c %u "$h" 2>/dev/null || echo unknown); '
        'test "$owner" = "$uid" || echo "$u:$h owner=$owner expected=$uid"; done',
        "Set each interactive user's home directory ownership to that user.",
        no_lines(
            "Interactive user home ownership is consistent.",
            "Home ownership findings found.",
        ),
    ),
    CommandCheckSpec(
        "AC-019",
        "Interactive User Home Write Permissions",
        "Access Control",
        "Detect group/world writable interactive user home directories.",
        "awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1\":\"$6}' "
        '/etc/passwd | while IFS=: read -r u h; do test -d "$h" || continue; '
        'find "$h" -maxdepth 0 -perm /022 -printf "$u:%m:%p\\n" 2>/dev/null; done',
        "Remove group/world write permissions from interactive user home directories.",
        no_lines(
            "Interactive user home directories are not group/world writable.",
            "Writable home directories found.",
        ),
    ),
    CommandCheckSpec(
        "SSH-001",
        "OpenSSH Effective Configuration",
        "SSH Hardening",
        "Collect effective sshd configuration with sshd -T.",
        SSHD_T,
        "Install OpenSSH server or fix sshd configuration parsing errors.",
        warning_inventory("Effective sshd configuration collected."),
    ),
    CommandCheckSpec(
        "SSH-002",
        "SSH Root Login",
        "SSH Hardening",
        "Verify SSH root login is disabled or key-restricted.",
        sshd_t_filter("grep -i '^permitrootlogin ' || echo sshd-unavailable"),
        "Set PermitRootLogin no or prohibit-password in sshd_config.",
        sshd_effective_value(
            "permitrootlogin", {"no", "prohibit-password", "without-password"}
        ),
    ),
    CommandCheckSpec(
        "SSH-003",
        "SSH Password Authentication",
        "SSH Hardening",
        "Verify SSH password authentication is disabled where policy requires keys.",
        sshd_t_filter("grep -i '^passwordauthentication ' || echo sshd-unavailable"),
        "Set PasswordAuthentication no when key-based SSH is required.",
        sshd_effective_value("passwordauthentication", {"no"}),
    ),
    CommandCheckSpec(
        "SSH-004",
        "SSH Empty Passwords",
        "SSH Hardening",
        "Verify SSH empty passwords are disabled.",
        sshd_t_filter("grep -i '^permitemptypasswords ' || echo sshd-unavailable"),
        "Set PermitEmptyPasswords no in sshd_config.",
        sshd_effective_value("permitemptypasswords", {"no"}),
    ),
    CommandCheckSpec(
        "SSH-005",
        "SSH X11 Forwarding",
        "SSH Hardening",
        "Verify X11 forwarding is disabled.",
        sshd_t_filter("grep -i '^x11forwarding ' || echo sshd-unavailable"),
        "Set X11Forwarding no in sshd_config unless explicitly required.",
        sshd_effective_value("x11forwarding", {"no"}),
    ),
    CommandCheckSpec(
        "SSH-006",
        "SSH MaxAuthTries",
        "SSH Hardening",
        "Verify SSH MaxAuthTries is within threshold.",
        sshd_t_filter(
            'awk \'tolower($1)=="maxauthtries" '
            '{found=1; print "MAXAUTHTRIES="$2} '
            'END {if (!found) print "sshd-unavailable"}\''
        ),
        "Set MaxAuthTries to 4 or fewer unless policy requires otherwise.",
        pass_int_max("MAXAUTHTRIES", "ssh_max_auth_tries", 4),
    ),
    CommandCheckSpec(
        "SSH-007",
        "SSH Weak Ciphers",
        "SSH Hardening",
        "Detect weak SSH ciphers in the effective configuration.",
        sshd_t_filter("grep -i '^ciphers ' || echo sshd-unavailable"),
        "Remove CBC, RC4, and 3DES ciphers from sshd_config.",
        lambda raw, exit_code, settings: (
            (STATUS_WARNING, "sshd -T was unavailable.", "", None)
            if "sshd-unavailable" in raw
            else (STATUS_FAIL, "Weak SSH cipher appears enabled.", "", None)
            if re.search(r"(cbc|3des|arcfour)", raw, re.I)
            else (
                STATUS_PASS,
                "No weak SSH ciphers detected in effective config.",
                "",
                None,
            )
        ),
    ),
    CommandCheckSpec(
        "SSH-008",
        "SSH LoginGraceTime",
        "SSH Hardening",
        "Verify SSH LoginGraceTime is within threshold.",
        sshd_t_filter(
            'awk \'tolower($1)=="logingracetime" '
            '{found=1; gsub(/s$/, "", $2); print "LOGINGRACETIME="$2} '
            'END {if (!found) print "sshd-unavailable"}\''
        ),
        "Set LoginGraceTime to 60 seconds or less.",
        pass_int_max("LOGINGRACETIME", "ssh_login_grace_time_seconds", 60, "seconds"),
    ),
    CommandCheckSpec(
        "SSH-009",
        "SSH ClientAliveInterval",
        "SSH Hardening",
        "Verify SSH idle keepalive interval is configured.",
        sshd_t_filter(
            'awk \'tolower($1)=="clientaliveinterval" '
            '{found=1; print "CLIENTALIVEINTERVAL="$2} '
            'END {if (!found) print "sshd-unavailable"}\''
        ),
        "Set ClientAliveInterval to a positive value not exceeding policy.",
        pass_int_between(
            "CLIENTALIVEINTERVAL",
            1,
            "ssh_client_alive_interval",
            900,
            "seconds",
        ),
    ),
    CommandCheckSpec(
        "SSH-010",
        "SSH Hostbased Authentication",
        "SSH Hardening",
        "Verify hostbased SSH authentication is disabled.",
        sshd_t_filter("grep -i '^hostbasedauthentication ' || echo sshd-unavailable"),
        "Set HostbasedAuthentication no in sshd_config.",
        sshd_effective_value("hostbasedauthentication", {"no"}),
    ),
    CommandCheckSpec(
        "SSH-011",
        "SSH IgnoreRhosts",
        "SSH Hardening",
        "Verify SSH ignores rhosts-style trust files.",
        sshd_t_filter("grep -i '^ignorerhosts ' || echo sshd-unavailable"),
        "Set IgnoreRhosts yes in sshd_config.",
        sshd_effective_value("ignorerhosts", {"yes"}),
    ),
    CommandCheckSpec(
        "SSH-012",
        "SSH PermitUserEnvironment",
        "SSH Hardening",
        "Verify user-controlled SSH environment files are disabled.",
        sshd_t_filter("grep -i '^permituserenvironment ' || echo sshd-unavailable"),
        "Set PermitUserEnvironment no in sshd_config.",
        sshd_effective_value("permituserenvironment", {"no"}),
    ),
    CommandCheckSpec(
        "SSH-013",
        "SSH TCP Forwarding",
        "SSH Hardening",
        "Detect whether SSH TCP forwarding is enabled.",
        sshd_t_filter("grep -i '^allowtcpforwarding ' || echo sshd-unavailable"),
        "Set AllowTcpForwarding no unless forwarding is explicitly required.",
        sshd_effective_value("allowtcpforwarding", {"no"}, fail_if_missing=False),
    ),
    CommandCheckSpec(
        "SSH-014",
        "SSH GatewayPorts",
        "SSH Hardening",
        "Verify SSH GatewayPorts is disabled.",
        sshd_t_filter("grep -i '^gatewayports ' || echo sshd-unavailable"),
        "Set GatewayPorts no in sshd_config.",
        sshd_effective_value("gatewayports", {"no"}),
    ),
    CommandCheckSpec(
        "SSH-015",
        "SSH LogLevel",
        "SSH Hardening",
        "Verify SSH daemon logging is INFO or VERBOSE.",
        sshd_t_filter("grep -i '^loglevel ' || echo sshd-unavailable"),
        "Set LogLevel INFO or VERBOSE in sshd_config.",
        sshd_effective_value("loglevel", {"info", "verbose"}),
    ),
    CommandCheckSpec(
        "SSH-016",
        "SSH Weak MACs",
        "SSH Hardening",
        "Detect weak SSH MAC algorithms in effective configuration.",
        sshd_t_filter("grep -i '^macs ' || echo sshd-unavailable"),
        "Remove MD5, UMAC-64, and encrypt-and-MAC algorithms from sshd_config.",
        lambda raw, exit_code, settings: (
            (STATUS_WARNING, "sshd -T was unavailable.", "", None)
            if "sshd-unavailable" in raw
            else (STATUS_FAIL, "Weak SSH MAC appears enabled.", "", None)
            if re.search(r"(hmac-md5|umac-64)", raw, re.I)
            else (
                STATUS_PASS,
                "No weak SSH MACs detected in effective config.",
                "",
                None,
            )
        ),
    ),
    CommandCheckSpec(
        "SSH-017",
        "SSH Weak Key Exchanges",
        "SSH Hardening",
        "Detect weak SSH key exchange algorithms in effective configuration.",
        sshd_t_filter("grep -i '^kexalgorithms ' || echo sshd-unavailable"),
        "Remove SHA1, group1, and weak diffie-hellman KEX algorithms.",
        lambda raw, exit_code, settings: (
            (STATUS_WARNING, "sshd -T was unavailable.", "", None)
            if "sshd-unavailable" in raw
            else (STATUS_FAIL, "Weak SSH key exchange appears enabled.", "", None)
            if re.search(
                r"(sha1|diffie-hellman-group1|diffie-hellman-group14-sha1)", raw, re.I
            )
            else (STATUS_PASS, "No weak SSH key exchanges detected.", "", None)
        ),
    ),
    CommandCheckSpec(
        "AU-001",
        "Auditd Service",
        "Audit Logging",
        "Verify auditd is installed and active.",
        "command -v auditctl >/dev/null 2>&1 || "
        "{ echo not-installed; exit 0; }; "
        "systemctl is-active auditd 2>/dev/null || true",
        "Install and enable auditd where audit policy requires it.",
        service_active("auditd"),
    ),
    CommandCheckSpec(
        "AU-002",
        "Audit Rule Inventory",
        "Audit Logging",
        "Verify audit rules are present.",
        "auditctl -l 2>/dev/null | sed -n '1,80p'",
        "Deploy baseline audit rules for privileged actions and sensitive files.",
        any_lines_warning("Audit rules are present and require policy review."),
    ),
    CommandCheckSpec(
        "AU-003",
        "Journald Persistent Storage",
        "Audit Logging",
        "Verify journald persistent storage is enabled.",
        "grep -E '^Storage=persistent' /etc/systemd/journald.conf "
        "/etc/systemd/journald.conf.d/*.conf 2>/dev/null",
        "Set Storage=persistent for systemd-journald where journald is used.",
        pass_if_exit_zero(
            "journald persistent storage is configured.",
            "journald persistent storage was not confirmed.",
        ),
    ),
    CommandCheckSpec(
        "AU-004",
        "Syslog Service",
        "Audit Logging",
        "Verify a syslog service is active when installed.",
        "for s in rsyslog syslog-ng; do "
        "systemctl is-active $s 2>/dev/null && echo active && exit 0; "
        "done; echo inactive",
        "Enable rsyslog or syslog-ng when host logging policy requires it.",
        pass_line_equals(
            "active",
            "A syslog service is active.",
            "No active syslog service detected.",
        ),
    ),
    CommandCheckSpec(
        "AU-005",
        "Writable Log Files",
        "Audit Logging",
        "Detect world-writable files under /var/log.",
        "find /var/log -xdev -type f -perm -0002 -print 2>/dev/null | head -100",
        "Remove world write permissions from log files.",
        no_lines(
            "No world-writable log files found.", "World-writable log files found."
        ),
    ),
    CommandCheckSpec(
        "AU-006",
        "Auditd Boot Enablement",
        "Audit Logging",
        "Verify auditd is enabled to start at boot when installed.",
        "command -v auditctl >/dev/null 2>&1 || { echo not-installed; exit 0; }; "
        "systemctl is-enabled auditd 2>/dev/null || true",
        "Enable auditd at boot where audit policy requires it.",
        lambda raw, exit_code, settings: (
            (STATUS_FAIL, "auditd is not installed.", "", None)
            if "not-installed" in raw
            else (STATUS_PASS, "auditd is enabled at boot.", "", None)
            if any(line.strip() == "enabled" for line in raw.splitlines())
            else (STATUS_FAIL, "auditd is not enabled at boot.", "", None)
        ),
    ),
    CommandCheckSpec(
        "AU-007",
        "Audit Failure Mode",
        "Audit Logging",
        "Review auditd failure handling configuration.",
        "grep -E '^(disk_full_action|disk_error_action|space_left_action|"
        "admin_space_left_action)[[:space:]]*=' "
        "/etc/audit/auditd.conf 2>/dev/null || echo auditd-conf-unavailable",
        "Set auditd disk and space failure actions according to policy.",
        lambda raw, exit_code, settings: (
            (STATUS_WARNING, "auditd.conf was unavailable for review.", "", None)
            if "auditd-conf-unavailable" in raw
            else (
                STATUS_WARNING,
                "auditd failure handling collected for review.",
                "",
                None,
            )
        ),
    ),
    CommandCheckSpec(
        "AU-008",
        "Remote Syslog Forwarding",
        "Audit Logging",
        "Detect rsyslog/syslog-ng remote forwarding configuration.",
        "grep -RhsE '(@@?|omfwd|destination\\s+d_)' "
        "/etc/rsyslog* /etc/syslog-ng 2>/dev/null | head -50",
        "Configure remote log forwarding where centralized logging is required.",
        any_lines_warning("Remote syslog forwarding evidence found."),
    ),
    CommandCheckSpec(
        "AU-009",
        "Logrotate Configuration",
        "Audit Logging",
        "Verify logrotate configuration exists for log retention operations.",
        "test -f /etc/logrotate.conf && echo present || echo missing",
        "Install/configure logrotate or equivalent log retention tooling.",
        pass_line_equals(
            "present",
            "logrotate configuration exists.",
            "logrotate configuration was not found.",
        ),
    ),
    CommandCheckSpec(
        "CM-001",
        "Host Firewall",
        "Configuration Management",
        "Verify a Linux host firewall is active or rules exist.",
        "printf 'ufw='; systemctl is-active ufw 2>/dev/null || true; "
        "printf '\\nfirewalld='; "
        "systemctl is-active firewalld 2>/dev/null || true; "
        "printf '\\nnft_rules='; "
        "nft list ruleset >/dev/null 2>&1 && echo yes || echo no; "
        "printf 'iptables_rules='; "
        "iptables -S 2>/dev/null | grep -q -- '^-A' && echo yes || echo no",
        "Enable ufw, firewalld, nftables, or iptables rules per host policy.",
        firewall_evaluator,
    ),
    CommandCheckSpec(
        "CM-002",
        "Automatic Update Tooling",
        "Configuration Management",
        "Detect automatic security update tooling.",
        "dpkg -s unattended-upgrades >/dev/null 2>&1 && "
        "echo unattended-upgrades=installed; "
        "rpm -q dnf-automatic >/dev/null 2>&1 && echo dnf-automatic=installed; "
        "rpm -q yum-cron >/dev/null 2>&1 && echo yum-cron=installed; "
        "systemctl list-timers 2>/dev/null | grep -qi zypper && "
        "echo zypper=patch-timer; true",
        "Install and configure automatic security updates or document patch SLAs.",
        auto_updates_evaluator,
    ),
    CommandCheckSpec(
        "CM-003",
        "Package Repository Signature Checks",
        "Configuration Management",
        "Verify repository package signature checking where detectable.",
        "if command -v apt-get >/dev/null 2>&1; then "
        "grep -Rqs '^deb \\[trusted=yes' "
        "/etc/apt/sources.list /etc/apt/sources.list.d && "
        "echo apt_signed=no || echo apt_signed=yes; "
        "elif test -d /etc/yum.repos.d; then "
        "grep -Rhs '^gpgcheck=0' /etc/yum.repos.d && "
        "echo rpm_gpgcheck=no || echo rpm_gpgcheck=yes; else echo unknown; fi",
        "Require signed repositories and enable gpgcheck for RPM repositories.",
        package_signing_evaluator,
    ),
    CommandCheckSpec(
        "CM-004",
        "Disk Usage Threshold",
        "Configuration Management",
        "Warn when filesystems are near capacity.",
        "df -P -x tmpfs -x devtmpfs",
        "Free disk space or expand filesystems that exceed policy thresholds.",
        disk_usage_evaluator,
    ),
    CommandCheckSpec(
        "SV-001",
        "Telnet Service Absent",
        "Services",
        "Ensure telnet server components are not installed or active.",
        "command -v in.telnetd 2>/dev/null; "
        "systemctl list-unit-files 2>/dev/null | grep -i telnet || true",
        "Remove telnet server packages and use SSH instead.",
        no_lines(
            "Telnet service components were not detected.",
            "Telnet service components were detected.",
        ),
    ),
    CommandCheckSpec(
        "SV-002",
        "RSH/Rexec Services Absent",
        "Services",
        "Ensure legacy rsh/rexec services are absent.",
        "systemctl list-unit-files 2>/dev/null | grep -Ei '(rsh|rexec|rlogin)'",
        "Remove rsh, rexec, and rlogin server packages.",
        no_lines(
            "Legacy rsh/rexec/rlogin services not detected.",
            "Legacy remote shell services found.",
        ),
    ),
    CommandCheckSpec(
        "SV-003",
        "TFTP Service Absent",
        "Services",
        "Ensure TFTP service is absent unless explicitly required.",
        "systemctl list-unit-files 2>/dev/null | grep -Ei 'tftp'",
        "Remove or disable TFTP unless there is a documented exception.",
        no_lines("TFTP service not detected.", "TFTP service entries found."),
    ),
    CommandCheckSpec(
        "SV-004",
        "Avahi/mDNS Service",
        "Services",
        "Detect Avahi/mDNS service exposure.",
        "systemctl is-active avahi-daemon 2>/dev/null || true",
        "Disable avahi-daemon unless local service discovery is required.",
        fail_line_equals(
            "active",
            "Avahi/mDNS service is not active.",
            "Avahi/mDNS service is active.",
        ),
    ),
    CommandCheckSpec(
        "SV-005",
        "Listening Services Inventory",
        "Services",
        "Collect listening TCP/UDP services for exposure review.",
        "ss -tulpen 2>/dev/null | sed -n '1,120p' || "
        "netstat -tulpen 2>/dev/null | sed -n '1,120p'",
        "Review listening services and restrict unnecessary exposure.",
        warning_inventory("Listening services inventory collected for review."),
    ),
    CommandCheckSpec(
        "SV-006",
        "Cron Service",
        "Services",
        "Verify cron service is active where scheduled jobs are used.",
        "for s in cron crond; do "
        "systemctl is-active $s 2>/dev/null && echo active && exit 0; "
        "done; echo inactive",
        "Enable cron/crond when scheduled jobs are expected; otherwise "
        "document exception.",
        pass_line_equals(
            "active", "Cron service is active.", "Cron service is not active."
        ),
    ),
    CommandCheckSpec(
        "SV-007",
        "Docker Socket Exposure",
        "Services",
        "Check Docker socket permissions if Docker is present.",
        "test -S /var/run/docker.sock && "
        "stat -c '%a %U %G %n' /var/run/docker.sock || true",
        "Restrict Docker socket access to authorized administrators only.",
        any_lines_warning("Docker socket exists and requires access review."),
    ),
    CommandCheckSpec(
        "SV-008",
        "NFS Server Service",
        "Services",
        "Ensure NFS server service is not active unless explicitly required.",
        "systemctl is-active nfs-server 2>/dev/null || true",
        "Disable nfs-server unless there is a documented business requirement.",
        service_absent_or_inactive("nfs-server"),
    ),
    CommandCheckSpec(
        "SV-009",
        "SMB Server Service",
        "Services",
        "Ensure SMB service is not active unless explicitly required.",
        "systemctl is-active smb smbd 2>/dev/null || true",
        "Disable smb/smbd unless there is a documented business requirement.",
        service_absent_or_inactive("smb/smbd"),
    ),
    CommandCheckSpec(
        "SV-010",
        "CUPS Print Service",
        "Services",
        "Ensure CUPS print service is not active unless explicitly required.",
        "systemctl is-active cups 2>/dev/null || true",
        "Disable cups unless printing is required on the host.",
        service_absent_or_inactive("cups"),
    ),
    CommandCheckSpec(
        "SV-011",
        "RPCbind Service",
        "Services",
        "Ensure rpcbind is not active unless explicitly required.",
        "systemctl is-active rpcbind 2>/dev/null || true",
        "Disable rpcbind unless RPC-dependent services are required.",
        service_absent_or_inactive("rpcbind"),
    ),
    CommandCheckSpec(
        "SV-012",
        "FTP Server Service",
        "Services",
        "Ensure common FTP server services are not active.",
        "systemctl is-active vsftpd proftpd pure-ftpd 2>/dev/null || true",
        "Disable FTP server services and use secure transfer protocols.",
        service_absent_or_inactive("ftp server"),
    ),
    CommandCheckSpec(
        "FS-001",
        "World-Writable Directories Without Sticky Bit",
        "Filesystem",
        "Find world-writable directories missing the sticky bit.",
        "find /tmp /var/tmp /dev/shm -xdev -type d "
        "-perm -0002 ! -perm -1000 -print 2>/dev/null",
        "Set sticky bit on shared writable directories or remove world write.",
        no_lines(
            "No world-writable shared dirs missing sticky bit found.",
            "World-writable directories without sticky bit found.",
        ),
    ),
    CommandCheckSpec(
        "FS-002",
        "SUID/SGID File Inventory",
        "Filesystem",
        "Inventory SUID/SGID files for privileged executable review.",
        "find /bin /sbin /usr/bin /usr/sbin /usr/local -xdev -type f "
        "\\( -perm -4000 -o -perm -2000 \\) -print 2>/dev/null | head -200",
        "Review SUID/SGID files and remove unnecessary privileged bits.",
        any_lines_warning("SUID/SGID files require review."),
    ),
    CommandCheckSpec(
        "FS-003",
        "Unowned System Files",
        "Filesystem",
        "Find unowned files in key system paths.",
        "find /etc /var /usr/local -xdev "
        "\\( -nouser -o -nogroup \\) -print 2>/dev/null | head -100",
        "Assign valid ownership or remove unowned files.",
        no_lines("No unowned files found in key system paths.", "Unowned files found."),
    ),
    CommandCheckSpec(
        "FS-004",
        "Temporary Filesystem Mount Options",
        "Filesystem",
        "Review /tmp, /var/tmp, and /dev/shm mount options.",
        "findmnt -no TARGET,OPTIONS /tmp /var/tmp /dev/shm 2>/dev/null",
        "Use nodev,nosuid,noexec where compatible with workload requirements.",
        mount_options_evaluator,
    ),
    CommandCheckSpec(
        "FS-005",
        "SSH Server Config Permissions",
        "Filesystem",
        "Verify sshd_config ownership and permissions are restrictive.",
        "stat -c '%a %U %G %n' /etc/ssh/sshd_config "
        "/etc/ssh/sshd_config.d/*.conf 2>/dev/null",
        "Set sshd_config files to root ownership and restrictive permissions.",
        lambda raw, exit_code, settings: (
            (STATUS_WARNING, "No sshd_config files were returned for review.", "", None)
            if not raw.strip()
            else (STATUS_FAIL, "SSH config file permissions require review.", "", None)
            if any(
                line.split()[0] not in {"600", "640", "644", "400", "440"}
                or line.split()[1] != "root"
                or line.split()[2] != "root"
                for line in raw.splitlines()
                if line.strip()
            )
            else (
                STATUS_PASS,
                "SSH config file permissions look restrictive.",
                "",
                None,
            )
        ),
    ),
    CommandCheckSpec(
        "FS-006",
        "Boot Directory Permissions",
        "Filesystem",
        "Verify /boot ownership and permissions are restrictive when present.",
        "test -d /boot && stat -c '%a %U %G %n' /boot || true",
        "Set /boot ownership to root and remove group/world write access.",
        lambda raw, exit_code, settings: (
            (STATUS_WARNING, "/boot was not present or not visible.", "", None)
            if not raw.strip()
            else (STATUS_FAIL, "/boot permissions require review.", "", None)
            if any(
                len(parts := line.split()) >= 4
                and (
                    parts[1] != "root"
                    or parts[2] != "root"
                    or parts[0][-1] in {"2", "3", "6", "7"}
                )
                for line in raw.splitlines()
            )
            else (STATUS_PASS, "/boot permissions look restrictive.", "", None)
        ),
    ),
    CommandCheckSpec(
        "FS-007",
        "Netrc File Presence",
        "Filesystem",
        "Detect .netrc files that can expose machine credentials.",
        "find /home /root -xdev -name .netrc -print 2>/dev/null | head -100",
        "Remove .netrc files or restrict and document them if required.",
        no_lines("No .netrc files found.", ".netrc files found."),
    ),
    CommandCheckSpec(
        "FS-008",
        "Cron File Write Permissions",
        "Filesystem",
        "Detect group/world writable system cron files or directories.",
        "for p in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly "
        '/etc/cron.monthly /etc/cron.d; do test -e "$p" || continue; '
        'find "$p" -maxdepth 1 -perm /022 -print 2>/dev/null; done',
        "Remove group/world write permissions from system cron paths.",
        no_lines(
            "No group/world writable system cron paths found.",
            "Writable cron paths found.",
        ),
    ),
    CommandCheckSpec(
        "FS-009",
        "Cron Allow/Deny File Permissions",
        "Filesystem",
        "Detect loose permissions on cron and at allow/deny files.",
        "for p in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do "
        'test -e "$p" || continue; stat -c \'%a %U %G %n\' "$p"; done',
        "Restrict cron/at allow and deny files to root ownership and mode 600/640.",
        lambda raw, exit_code, settings: (
            (STATUS_PASS, "No cron/at allow-deny files found for review.", "", None)
            if not raw.strip()
            else (
                STATUS_FAIL,
                "cron/at allow-deny permissions require review.",
                "",
                None,
            )
            if any(
                line.split()[0] not in {"600", "640"}
                or line.split()[1] != "root"
                or line.split()[2] != "root"
                for line in raw.splitlines()
                if line.strip()
            )
            else (
                STATUS_PASS,
                "cron/at allow-deny file permissions look restrictive.",
                "",
                None,
            )
        ),
    ),
    CommandCheckSpec(
        "FS-010",
        "Cramfs Kernel Module",
        "Filesystem",
        "Verify cramfs filesystem module loading is disabled or unavailable.",
        module_probe_command("cramfs"),
        "Disable cramfs module loading unless required.",
        module_disabled_evaluator("cramfs"),
    ),
    CommandCheckSpec(
        "FS-011",
        "UDF Kernel Module",
        "Filesystem",
        "Verify udf filesystem module loading is disabled or unavailable.",
        module_probe_command("udf"),
        "Disable udf module loading unless removable media support is required.",
        module_disabled_evaluator("udf"),
    ),
    CommandCheckSpec(
        "FS-012",
        "USB Storage Kernel Module",
        "Filesystem",
        "Verify usb-storage module loading is disabled or unavailable.",
        module_probe_command("usb-storage"),
        "Disable usb-storage module loading unless removable media is required.",
        module_disabled_evaluator("usb-storage"),
    ),
    CommandCheckSpec(
        "NH-001",
        "IPv4 Forwarding",
        "Network Hardening",
        "Verify IPv4 forwarding is disabled unless host is a router.",
        "sysctl -n net.ipv4.ip_forward 2>/dev/null | "
        "awk '{print \"net.ipv4.ip_forward=\"$1}'",
        "Set net.ipv4.ip_forward=0 unless routing is required.",
        pass_value("net.ipv4.ip_forward", "0"),
    ),
    CommandCheckSpec(
        "NH-002",
        "IPv6 Forwarding",
        "Network Hardening",
        "Verify IPv6 forwarding is disabled unless host is a router.",
        "sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null | "
        "awk '{print \"net.ipv6.conf.all.forwarding=\"$1}'",
        "Set net.ipv6.conf.all.forwarding=0 unless routing is required.",
        pass_value("net.ipv6.conf.all.forwarding", "0"),
    ),
    CommandCheckSpec(
        "NH-003",
        "ICMP Redirect Acceptance",
        "Network Hardening",
        "Verify ICMP redirect acceptance is disabled.",
        "sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null | "
        "awk '{print \"net.ipv4.conf.all.accept_redirects=\"$1}'",
        "Set net.ipv4.conf.all.accept_redirects=0.",
        pass_value("net.ipv4.conf.all.accept_redirects", "0"),
    ),
    CommandCheckSpec(
        "NH-004",
        "ICMP Redirect Sending",
        "Network Hardening",
        "Verify ICMP redirect sending is disabled.",
        "sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null | "
        "awk '{print \"net.ipv4.conf.all.send_redirects=\"$1}'",
        "Set net.ipv4.conf.all.send_redirects=0.",
        pass_value("net.ipv4.conf.all.send_redirects", "0"),
    ),
    CommandCheckSpec(
        "NH-005",
        "Source Routing",
        "Network Hardening",
        "Verify source-routed packet acceptance is disabled.",
        "sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null | "
        "awk '{print \"net.ipv4.conf.all.accept_source_route=\"$1}'",
        "Set net.ipv4.conf.all.accept_source_route=0.",
        pass_value("net.ipv4.conf.all.accept_source_route", "0"),
    ),
    CommandCheckSpec(
        "NH-006",
        "TCP SYN Cookies",
        "Network Hardening",
        "Verify TCP SYN cookies are enabled.",
        "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null | "
        "awk '{print \"net.ipv4.tcp_syncookies=\"$1}'",
        "Set net.ipv4.tcp_syncookies=1.",
        pass_value("net.ipv4.tcp_syncookies", "1"),
    ),
    CommandCheckSpec(
        "NH-007",
        "Kernel Dmesg Restriction",
        "Network Hardening",
        "Verify unprivileged dmesg access is restricted.",
        "sysctl -n kernel.dmesg_restrict 2>/dev/null | "
        "awk '{print \"kernel.dmesg_restrict=\"$1}'",
        "Set kernel.dmesg_restrict=1.",
        pass_value("kernel.dmesg_restrict", "1"),
    ),
    CommandCheckSpec(
        "NH-008",
        "Ptrace Scope",
        "Network Hardening",
        "Verify ptrace scope is restricted where Yama is available.",
        "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null | "
        "awk '{print \"kernel.yama.ptrace_scope=\"$1}'",
        "Set kernel.yama.ptrace_scope=1 or stronger where supported.",
        pass_value_in(
            "kernel.yama.ptrace_scope",
            {"1", "2", "3"},
            "ptrace_scope_allowed_values",
        ),
    ),
    CommandCheckSpec(
        "NH-009",
        "Address Space Layout Randomization",
        "Network Hardening",
        "Verify ASLR is enabled.",
        "cat /proc/sys/kernel/randomize_va_space 2>/dev/null | "
        "awk '{print \"kernel.randomize_va_space=\"$1}'",
        "Set kernel.randomize_va_space=2.",
        pass_value("kernel.randomize_va_space", "2"),
    ),
    CommandCheckSpec(
        "NH-010",
        "Secure ICMP Redirect Acceptance",
        "Network Hardening",
        "Verify secure ICMP redirect acceptance is disabled.",
        "sysctl -n net.ipv4.conf.all.secure_redirects 2>/dev/null | "
        "awk '{print \"net.ipv4.conf.all.secure_redirects=\"$1}'",
        "Set net.ipv4.conf.all.secure_redirects=0.",
        pass_value("net.ipv4.conf.all.secure_redirects", "0"),
    ),
    CommandCheckSpec(
        "NH-011",
        "Reverse Path Filtering",
        "Network Hardening",
        "Verify IPv4 reverse path filtering is enabled.",
        "sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null | "
        "awk '{print \"net.ipv4.conf.all.rp_filter=\"$1}'",
        "Set net.ipv4.conf.all.rp_filter=1 where compatible with routing policy.",
        pass_value_in(
            "net.ipv4.conf.all.rp_filter",
            {"1"},
            "reverse_path_filter_values",
        ),
    ),
    CommandCheckSpec(
        "NH-012",
        "Martian Packet Logging",
        "Network Hardening",
        "Verify martian packet logging is enabled for IPv4.",
        "sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null | "
        "awk '{print \"net.ipv4.conf.all.log_martians=\"$1}'",
        "Set net.ipv4.conf.all.log_martians=1 where compatible with policy.",
        pass_value("net.ipv4.conf.all.log_martians", "1"),
    ),
    CommandCheckSpec(
        "NH-013",
        "IPv6 Redirect Acceptance",
        "Network Hardening",
        "Verify IPv6 redirect acceptance is disabled.",
        "sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null | "
        "awk '{print \"net.ipv6.conf.all.accept_redirects=\"$1}'",
        "Set net.ipv6.conf.all.accept_redirects=0.",
        pass_value("net.ipv6.conf.all.accept_redirects", "0"),
    ),
    CommandCheckSpec(
        "NH-014",
        "IPv6 Source Routing",
        "Network Hardening",
        "Verify IPv6 source-routed packet acceptance is disabled.",
        "sysctl -n net.ipv6.conf.all.accept_source_route 2>/dev/null | "
        "awk '{print \"net.ipv6.conf.all.accept_source_route=\"$1}'",
        "Set net.ipv6.conf.all.accept_source_route=0.",
        pass_value("net.ipv6.conf.all.accept_source_route", "0"),
    ),
    CommandCheckSpec(
        "NH-015",
        "Protected Hardlinks",
        "Network Hardening",
        "Verify kernel hardlink protection is enabled.",
        "sysctl -n fs.protected_hardlinks 2>/dev/null | "
        "awk '{print \"fs.protected_hardlinks=\"$1}'",
        "Set fs.protected_hardlinks=1.",
        pass_value("fs.protected_hardlinks", "1"),
    ),
    CommandCheckSpec(
        "NH-016",
        "Protected Symlinks",
        "Network Hardening",
        "Verify kernel symlink protection is enabled.",
        "sysctl -n fs.protected_symlinks 2>/dev/null | "
        "awk '{print \"fs.protected_symlinks=\"$1}'",
        "Set fs.protected_symlinks=1.",
        pass_value("fs.protected_symlinks", "1"),
    ),
    CommandCheckSpec(
        "SI-001",
        "Mandatory Access Control",
        "System Integrity",
        "Verify SELinux or AppArmor enforcement signal.",
        "if command -v getenforce >/dev/null 2>&1; then "
        "echo selinux=$(getenforce); fi; "
        "if command -v aa-status >/dev/null 2>&1; then "
        "aa-status --enabled >/dev/null 2>&1 && "
        "echo apparmor=enabled || echo apparmor=disabled; fi",
        "Enable SELinux or AppArmor where supported by the distribution.",
        security_module_evaluator,
    ),
    CommandCheckSpec(
        "SI-002",
        "File Integrity Tooling",
        "System Integrity",
        "Detect AIDE or Tripwire installation.",
        "command -v aide >/dev/null 2>&1 && echo aide; "
        "command -v tripwire >/dev/null 2>&1 && echo tripwire; true",
        "Install and configure file integrity monitoring if required by policy.",
        presence_requirement(
            "require_file_integrity_tooling",
            "File integrity tooling was detected.",
            "File integrity tooling was not detected.",
        ),
    ),
    CommandCheckSpec(
        "SI-003",
        "Antivirus/EDR Inventory",
        "System Integrity",
        "Collect visible antivirus or EDR process/package signals.",
        "for p in clamd freshclam falcon-sensor mdatp wdavdaemon sentinelone; "
        'do pgrep -a -x "$p" 2>/dev/null; done | head -50',
        "Install approved malware protection or EDR tooling where required.",
        presence_requirement(
            "require_malware_protection",
            "Malware protection or EDR process signals were detected.",
            "Malware protection or EDR process signals were not detected.",
        ),
    ),
    CommandCheckSpec(
        "SI-004",
        "Core Dump Restrictions",
        "System Integrity",
        "Verify core dump collection is restricted.",
        "sysctl -n fs.suid_dumpable 2>/dev/null | "
        "awk '{print \"fs.suid_dumpable=\"$1}'",
        "Set fs.suid_dumpable=0 and review systemd-coredump policy.",
        pass_value("fs.suid_dumpable", "0"),
    ),
    CommandCheckSpec(
        "SI-005",
        "Systemd Coredump Storage",
        "System Integrity",
        "Verify systemd-coredump storage is disabled or absent.",
        "grep -RhsE '^Storage=' /etc/systemd/coredump.conf "
        "/etc/systemd/coredump.conf.d 2>/dev/null || echo storage-unset",
        "Set Storage=none in systemd-coredump policy where core dumps are prohibited.",
        lambda raw, exit_code, settings: (
            (STATUS_PASS, "systemd-coredump Storage=none is configured.", "", None)
            if "Storage=none" in raw
            else (
                STATUS_WARNING,
                "systemd-coredump storage is unset; review policy.",
                "",
                None,
            )
            if "storage-unset" in raw
            else (STATUS_FAIL, "systemd-coredump storage is not disabled.", "", None)
        ),
    ),
    CommandCheckSpec(
        "SI-006",
        "PAM Password Quality",
        "System Integrity",
        "Detect PAM password quality controls.",
        "grep -RhsE 'pam_pwquality|pam_passwdqc|pam_cracklib' "
        "/etc/pam.d /etc/security 2>/dev/null | head -50",
        "Configure PAM password quality controls where local passwords are used.",
        presence_requirement(
            "require_pam_password_quality",
            "PAM password quality controls were detected.",
            "PAM password quality controls were not detected.",
        ),
    ),
    CommandCheckSpec(
        "SI-007",
        "Account Lockout Controls",
        "System Integrity",
        "Detect PAM faillock/tally account lockout controls.",
        "grep -RhsE 'pam_faillock|pam_tally2' "
        "/etc/pam.d /etc/security 2>/dev/null | head -50",
        "Configure account lockout controls for failed local authentication attempts.",
        presence_requirement(
            "require_account_lockout_controls",
            "PAM account lockout controls were detected.",
            "PAM account lockout controls were not detected.",
        ),
    ),
    CommandCheckSpec(
        "SI-008",
        "Failed Login Inventory",
        "System Integrity",
        "Collect a bounded failed-login signal when available.",
        "lastb -n 20 2>/dev/null || "
        "journalctl -n 50 _COMM=sshd 2>/dev/null | "
        "grep -i 'failed' | head -20 || true",
        "Review failed login activity and tune lockout/monitoring controls.",
        any_lines_warning("Failed-login evidence found for review."),
    ),
    CommandCheckSpec(
        "CT-001",
        "Virtualization Context",
        "Container and Virtualization",
        "Detect whether the target appears virtualized or containerized.",
        "systemd-detect-virt 2>/dev/null || echo unknown",
        "",
        warning_inventory("Virtualization/container context collected."),
    ),
    CommandCheckSpec(
        "CT-002",
        "Docker Privileged Containers",
        "Container and Virtualization",
        "Inventory privileged Docker containers when Docker is accessible.",
        "command -v docker >/dev/null 2>&1 && docker ps --quiet 2>/dev/null | "
        "xargs -r docker inspect --format "
        "'{{.Name}} privileged={{.HostConfig.Privileged}} "
        "network={{.HostConfig.NetworkMode}}' 2>/dev/null | "
        "grep 'privileged=true' || true",
        "Remove privileged containers unless a documented exception exists.",
        no_lines(
            "No privileged Docker containers detected.",
            "Privileged Docker containers detected.",
        ),
    ),
]


for spec in CHECKS:
    register_command_check(spec)
