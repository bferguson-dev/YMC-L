#!/usr/bin/env python3
"""
YMC-L CLI entry point.

Agentless Linux compliance evidence collection over SSH. The CLI mirrors the
YMC Windows scanner where practical so both tools can converge later.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import logging
import os
import platform
import re
import sys
from datetime import datetime
from pathlib import Path

import yaml
from colorama import Fore, Style, init as colorama_init

sys.path.insert(0, str(Path(__file__).parent))

from checks.registry import CheckRegistry
from connector.ssh_connector import SSHConnector, resolve_hostname
from engine.runner import ComplianceRunner, list_profiles
from reporters.html_reporter import HtmlReporter
from reporters.json_reporter import JsonReporter

colorama_init(autoreset=True)

TOOL_NAME = "YMC-L"
TOOL_VERSION = "0.1.0"

INSTALL_DIR = Path(__file__).parent
PROFILES_DIR = INSTALL_DIR / "profiles"
CONFIG_DIR = INSTALL_DIR / "config"
DEFAULT_CFG = CONFIG_DIR / "settings.yaml"
NAMED_CFG_DIR = CONFIG_DIR / "profiles"

USER_CFG_DIR = Path.home() / ".ymc-l"
USER_CFG_FILE = USER_CFG_DIR / "settings.yaml"
USER_PROFILES_DIR = USER_CFG_DIR / "profiles"

logger = logging.getLogger("ymc_l.main")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def _load_yaml(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as exc:
        print(f"{Fore.YELLOW}Warning: Could not parse {path}: {exc}{Style.RESET_ALL}")
        return {}


def _get(key: str, section: str, *dicts: dict, default=None):
    for data in dicts:
        section_data = data.get(section, {}) or {}
        if key in section_data and section_data[key] not in (None, ""):
            return section_data[key]
    return default


def _coerce_bool(value, setting_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    print(f"{Fore.RED}Error: Invalid boolean for {setting_name}: {value!r}")
    sys.exit(1)


def _coerce_int(value, setting_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        print(f"{Fore.RED}Error: Invalid integer for {setting_name}: {value!r}")
        sys.exit(1)


def load_named_profile(name: str) -> dict:
    for search_dir in [USER_PROFILES_DIR, NAMED_CFG_DIR]:
        candidate = search_dir / f"{name}.yaml"
        if candidate.exists():
            return _load_yaml(candidate)
    print(f"{Fore.RED}Error: Config profile '{name}' not found.{Style.RESET_ALL}")
    sys.exit(1)


def resolve_settings(args: argparse.Namespace) -> dict:
    defaults = _load_yaml(DEFAULT_CFG)
    user = _load_yaml(USER_CFG_FILE)
    config_name = (
        args.config
        or os.environ.get("COLLECTOR_CONFIG")
        or _get("config", "cli_defaults", user, defaults)
    )
    named = load_named_profile(config_name) if config_name else {}

    def resolve(
        cli_val, env_var: str, key: str, section: str = "cli_defaults", default=None
    ):
        if cli_val not in (None, False, ""):
            return cli_val
        env_val = os.environ.get(env_var)
        if env_val not in (None, ""):
            return env_val
        return _get(key, section, named, user, defaults, default=default)

    settings = {
        "domain": resolve(args.domain, "COLLECTOR_DOMAIN", "domain", default=""),
        "username": resolve(
            args.username, "COLLECTOR_USERNAME", "username", default=""
        ),
        "ssh_key": resolve(args.ssh_key, "COLLECTOR_SSH_KEY", "ssh_key", default=""),
        "profile": resolve(
            args.profile, "COLLECTOR_PROFILE", "profile", default="nist_800_53"
        ),
        "format": resolve(args.format, "COLLECTOR_FORMAT", "format", default="html"),
        "output_dir": resolve(
            args.output_dir, "COLLECTOR_OUTPUT_DIR", "output_dir", default=""
        ),
        "verbose": _coerce_bool(
            resolve(args.verbose, "COLLECTOR_VERBOSE", "verbose", default=False),
            "COLLECTOR_VERBOSE",
        ),
        "no_color": _coerce_bool(
            resolve(args.no_color, "COLLECTOR_NO_COLOR", "no_color", default=False),
            "COLLECTOR_NO_COLOR",
        ),
        "no_banner": _coerce_bool(
            resolve(args.no_banner, "COLLECTOR_NO_BANNER", "no_banner", default=False),
            "COLLECTOR_NO_BANNER",
        ),
        "prompt_password": _coerce_bool(
            resolve(
                args.prompt_password,
                "COLLECTOR_PROMPT_PASSWORD",
                "prompt_password",
                default=False,
            ),
            "COLLECTOR_PROMPT_PASSWORD",
        ),
        "use_sudo": _coerce_bool(
            resolve(args.use_sudo, "COLLECTOR_USE_SUDO", "use_sudo", default=False),
            "COLLECTOR_USE_SUDO",
        ),
        "strict_host_key_checking": _coerce_bool(
            resolve(
                args.strict_host_key_checking,
                "COLLECTOR_STRICT_HOST_KEY_CHECKING",
                "strict_host_key_checking",
                section="connection",
                default=True,
            ),
            "COLLECTOR_STRICT_HOST_KEY_CHECKING",
        ),
        "ssh_port": _coerce_int(
            resolve(args.ssh_port, "COLLECTOR_SSH_PORT", "ssh_port", default=22),
            "COLLECTOR_SSH_PORT",
        ),
        "connection_timeout": _coerce_int(
            resolve(
                None,
                "COLLECTOR_CONN_TIMEOUT",
                "connection_timeout",
                section="connection",
                default=30,
            ),
            "COLLECTOR_CONN_TIMEOUT",
        ),
        "read_timeout": _coerce_int(
            resolve(
                None,
                "COLLECTOR_READ_TIMEOUT",
                "read_timeout",
                section="connection",
                default=120,
            ),
            "COLLECTOR_READ_TIMEOUT",
        ),
        "max_password_age_days": _coerce_int(
            _get(
                "max_password_age_days", "evidence", named, user, defaults, default=90
            ),
            "max_password_age_days",
        ),
        "min_password_age_days": _coerce_int(
            _get("min_password_age_days", "evidence", named, user, defaults, default=1),
            "min_password_age_days",
        ),
        "password_warn_age_days": _coerce_int(
            _get(
                "password_warn_age_days",
                "evidence",
                named,
                user,
                defaults,
                default=7,
            ),
            "password_warn_age_days",
        ),
        "ssh_max_auth_tries": _coerce_int(
            _get("ssh_max_auth_tries", "evidence", named, user, defaults, default=4),
            "ssh_max_auth_tries",
        ),
        "ssh_login_grace_time_seconds": _coerce_int(
            _get(
                "ssh_login_grace_time_seconds",
                "evidence",
                named,
                user,
                defaults,
                default=60,
            ),
            "ssh_login_grace_time_seconds",
        ),
        "ssh_client_alive_interval": _coerce_int(
            _get(
                "ssh_client_alive_interval",
                "evidence",
                named,
                user,
                defaults,
                default=900,
            ),
            "ssh_client_alive_interval",
        ),
        "disk_usage_warning_percent": _coerce_int(
            _get(
                "disk_usage_warning_percent",
                "evidence",
                named,
                user,
                defaults,
                default=85,
            ),
            "disk_usage_warning_percent",
        ),
        "encrypt_method_allowed_values": _get(
            "encrypt_method_allowed_values",
            "evidence",
            named,
            user,
            defaults,
            default=["yescrypt", "sha512"],
        ),
        "umask_allowed_values": _get(
            "umask_allowed_values",
            "evidence",
            named,
            user,
            defaults,
            default=["027", "077"],
        ),
        "ptrace_scope_allowed_values": _get(
            "ptrace_scope_allowed_values",
            "evidence",
            named,
            user,
            defaults,
            default=["1", "2", "3"],
        ),
        "reverse_path_filter_values": _get(
            "reverse_path_filter_values",
            "evidence",
            named,
            user,
            defaults,
            default=["1"],
        ),
        "require_file_integrity_tooling": _coerce_bool(
            _get(
                "require_file_integrity_tooling",
                "evidence",
                named,
                user,
                defaults,
                default=False,
            ),
            "require_file_integrity_tooling",
        ),
        "require_malware_protection": _coerce_bool(
            _get(
                "require_malware_protection",
                "evidence",
                named,
                user,
                defaults,
                default=False,
            ),
            "require_malware_protection",
        ),
        "require_pam_password_quality": _coerce_bool(
            _get(
                "require_pam_password_quality",
                "evidence",
                named,
                user,
                defaults,
                default=False,
            ),
            "require_pam_password_quality",
        ),
        "require_account_lockout_controls": _coerce_bool(
            _get(
                "require_account_lockout_controls",
                "evidence",
                named,
                user,
                defaults,
                default=False,
            ),
            "require_account_lockout_controls",
        ),
        "filename_timestamp_format": _get(
            "filename_timestamp_format",
            "output",
            named,
            user,
            defaults,
            default="%Y%m%d_%H%M%S",
        ),
    }
    return settings


def resolve_output_dir(output_dir_setting: str) -> Path:
    if output_dir_setting:
        return Path(output_dir_setting).expanduser()
    home = Path.home()
    documents = home / "Documents"
    base = documents if platform.system() == "Windows" or documents.exists() else home
    return base / "Compliance Scans"


def create_scan_folder(output_root: Path, timestamp_fmt: str) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    base_name = f"scan_{datetime.now().strftime(timestamp_fmt)}"
    for suffix in [""] + [f"_{i:02d}" for i in range(1, 100)]:
        candidate = output_root / f"{base_name}{suffix}"
        try:
            candidate.mkdir(exist_ok=False)
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError(f"Could not allocate unique scan folder under {output_root}")


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "host"


def load_targets_from_csv(csv_path: Path, settings: dict) -> list[dict]:
    if not csv_path.exists():
        print(f"{Fore.RED}Error: CSV file not found: {csv_path}{Style.RESET_ALL}")
        sys.exit(1)

    with open(csv_path, newline="", encoding="utf-8") as handle:
        raw_lines = handle.readlines()
    lines = [
        line for line in raw_lines if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        print(f"{Fore.RED}Error: CSV file contains no targets: {csv_path}")
        sys.exit(1)

    csv_domain = ""
    if lines[0].strip().lower().startswith("domain,"):
        csv_domain = lines[0].split(",", 1)[1].strip()
        lines = lines[1:]

    reader = csv.DictReader(lines)
    required = {"host"}
    if not required.issubset(set(reader.fieldnames or [])):
        print(f"{Fore.RED}Error: CSV requires at least a host column.")
        sys.exit(1)

    targets = []
    for row in reader:
        host = (row.get("host") or "").strip()
        if not host:
            continue
        domain = settings["domain"] or csv_domain
        port = row.get("port") or settings["ssh_port"]
        targets.append(
            {
                "host": resolve_hostname(host, domain),
                "username": settings["username"] or (row.get("username") or "").strip(),
                "label": (row.get("label") or host).strip(),
                "port": _coerce_int(port, "csv port"),
                "ssh_key": settings["ssh_key"] or (row.get("ssh_key") or "").strip(),
                "notes": (row.get("notes") or "").strip(),
            }
        )
    return targets


def load_targets_from_host(host_arg: str, settings: dict) -> list[dict]:
    targets = []
    for raw_host in host_arg.split(","):
        host = raw_host.strip()
        if not host:
            continue
        resolved = resolve_hostname(host, settings["domain"])
        targets.append(
            {
                "host": resolved,
                "username": settings["username"],
                "label": host,
                "port": settings["ssh_port"],
                "ssh_key": settings["ssh_key"],
                "notes": "",
            }
        )
    return targets


def env_password_for(username: str) -> str:
    safe_user = re.sub(r"[^A-Za-z0-9]", "_", username).upper()
    return os.environ.get(f"COLLECTOR_PASSWORD_{safe_user}") or os.environ.get(
        "COLLECTOR_PASSWORD",
        "",
    )


def password_for(username: str, settings: dict, cache: dict[str, str]) -> str:
    if username in cache:
        return cache[username]
    password = env_password_for(username)
    if not password and settings["prompt_password"]:
        password = getpass.getpass(f"SSH password for {username}: ")
    cache[username] = password
    return password


def profile_path(profile_name: str) -> Path:
    for search_dir in [PROFILES_DIR]:
        candidate = search_dir / f"{profile_name}.yaml"
        if candidate.exists():
            return candidate
    print(f"{Fore.RED}Error: Compliance profile '{profile_name}' not found.")
    sys.exit(1)


def print_banner(settings: dict) -> None:
    if settings["no_banner"]:
        return
    print(f"{Fore.CYAN}{TOOL_NAME} v{TOOL_VERSION}{Style.RESET_ALL}")
    print("Agentless Linux SSH compliance evidence collector")


def print_profiles() -> None:
    print("Available compliance profiles:")
    for name in list_profiles(str(PROFILES_DIR)):
        print(f"  - {name}")


def print_config_profiles() -> None:
    print("Available config profiles:")
    seen = set()
    for search_dir in [NAMED_CFG_DIR, USER_PROFILES_DIR]:
        if search_dir.exists():
            for path in sorted(search_dir.glob("*.yaml")):
                if path.stem not in seen:
                    print(f"  - {path.stem} ({path})")
                    seen.add(path.stem)
    if not seen:
        print("  (none)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="YMC-L - Linux SSH compliance evidence collector"
    )
    targets = parser.add_mutually_exclusive_group()
    targets.add_argument("--host", help="Single host or comma-separated hosts")
    targets.add_argument("--csv", help="CSV target file")
    parser.add_argument("--username", help="SSH username")
    parser.add_argument("--domain", help="DNS suffix for bare hostnames")
    parser.add_argument("--ssh-port", type=int, help="SSH port")
    parser.add_argument("--ssh-key", help="SSH private key path")
    parser.add_argument("--profile", help="Compliance profile name")
    parser.add_argument("--format", choices=["html", "json", "both"])
    parser.add_argument("--output-dir", help="Report output root")
    parser.add_argument("--config", help="Named config profile")
    parser.add_argument("--prompt-password", action="store_true")
    parser.add_argument(
        "--use-sudo",
        action="store_true",
        help="Run remote check commands through non-interactive sudo",
    )
    parser.add_argument(
        "--no-strict-host-key-checking",
        dest="strict_host_key_checking",
        action="store_false",
        default=None,
        help="Accept unknown host keys for lab use",
    )
    parser.add_argument("--list-profiles", action="store_true")
    parser.add_argument("--list-configs", action="store_true")
    parser.add_argument("--list-checks", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-banner", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = resolve_settings(args)
    setup_logging(settings["verbose"])

    if args.list_profiles:
        print_profiles()
        return 0
    if args.list_configs:
        print_config_profiles()
        return 0
    if args.list_checks:
        for check_id in CheckRegistry.all_check_ids():
            print(check_id)
        return 0

    if not args.host and not args.csv:
        print(f"{Fore.RED}Error: Provide --host or --csv, or use --list-profiles.")
        return 2

    print_banner(settings)
    targets = (
        load_targets_from_csv(Path(args.csv).expanduser(), settings)
        if args.csv
        else load_targets_from_host(args.host, settings)
    )
    missing_user = [target["host"] for target in targets if not target["username"]]
    if missing_user:
        print(f"{Fore.RED}Error: Missing SSH username for: {', '.join(missing_user)}")
        return 2

    scan_folder = create_scan_folder(
        resolve_output_dir(settings["output_dir"]),
        settings["filename_timestamp_format"],
    )
    runner = ComplianceRunner(str(profile_path(settings["profile"])), settings)
    password_cache: dict[str, str] = {}
    had_runtime_error = False

    for target in targets:
        print(f"\nScanning {target['label']} ({target['host']}:{target['port']})")
        connector = SSHConnector(
            host=target["host"],
            username=target["username"],
            port=target["port"],
            key_filename=target["ssh_key"],
            connection_timeout=settings["connection_timeout"],
            read_timeout=settings["read_timeout"],
            strict_host_key_checking=settings["strict_host_key_checking"],
            use_sudo=settings["use_sudo"],
        )
        password = password_for(target["username"], settings, password_cache)
        ok, reason = connector.check_ssh_available(password=password or None)
        if not ok:
            had_runtime_error = True
            print(f"{Fore.RED}SSH precheck failed for {target['host']}: {reason}")
            connector.disconnect()
            continue

        scan_result = runner.scan(
            connector=connector,
            executed_by=target["username"],
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            host_label=target["label"],
        )
        connector.disconnect()

        if settings["format"] in ("json", "both"):
            print(f"JSON report: {JsonReporter(scan_folder).generate(scan_result)}")
        if settings["format"] in ("html", "both"):
            print(f"HTML report: {HtmlReporter(scan_folder).generate(scan_result)}")
        print(
            f"Summary: {scan_result.passed} passed, {scan_result.failed} failed, "
            f"{scan_result.warnings} warnings, {scan_result.errors} errors"
        )

    print(f"\nOutput folder: {scan_folder}")
    return 1 if had_runtime_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
