# YMC-L

YMC-L is an agentless Linux compliance evidence collector that connects over
SSH and runs programmatically checkable host controls. It is intentionally
structured like the YMC Windows scanner so the projects can merge into one
multi-platform scanner later.

YMC-L does not claim full compliance certification. It collects Linux-specific
technical evidence and maps that evidence to supported frameworks where the
control can be checked programmatically.

## Current Scope

- Linux targets over SSH only
- Password, SSH key, and SSH agent authentication paths
- HTML and JSON evidence reports
- CSV and direct host target input
- Framework-aware YAML profiles
- Offline tests plus opt-in live SSH integration tests

VMware/vCenter support is intentionally out of scope for this repository for
now. It can become a future connector and check pack.

## Profiles

Included starter profiles:

- `linux_baseline`
- `cis_linux`
- `nist_800_53`
- `nist_800_171`
- `fedramp_moderate`
- `pci_dss_4`
- `soc2`
- `hipaa`
- `cmmc_2`
- `iso_27001`
- `disa_stig`

Included distro-specific overlays for current lab targets:

- `cis_ubuntu_24_04`
- `cis_almalinux_10`

Framework profiles contain Linux-applicable, programmatically checkable mapped
evidence. The distro-specific overlays are local benchmark-style overlays for
Ubuntu 24.04 and AlmaLinux 10 and use local control IDs pending detailed
benchmark section review.

Profiles can also override scanner expectations per distro, including:

- threshold settings such as password age or SSH idle values
- accepted values for controls like `rp_filter` or `UMASK`
- status overrides, for example escalating a warning to a failure
- per-check metadata such as severity, expectation, rationale, and access level

## Quick Start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python main.py --list-profiles
python main.py --list-checks
```

Run a scan with SSH agent or key-based auth:

```bash
python main.py --host linux01.example.com \
  --username auditor \
  --ssh-key ~/.ssh/id_ed25519 \
  --profile nist_800_53 \
  --format both
```

Run with an interactive password prompt:

```bash
python main.py --host linux01.example.com \
  --username auditor \
  --prompt-password \
  --profile cis_linux
```

Run checks through non-interactive sudo when the scan user has approved sudo
rights:

```bash
python main.py --host linux01.example.com \
  --username auditor \
  --ssh-key ~/.ssh/id_ed25519 \
  --use-sudo \
  --profile linux_baseline
```

For lab hosts with unknown host keys:

```bash
python main.py --host 192.0.2.10 --username auditor --no-strict-host-key-checking
```

Use `--no-strict-host-key-checking` only when you intentionally accept the
host-key trust tradeoff, such as an isolated lab VM.

## Secrets

Do not put passwords in config files, docs, CSV files, shell history, or command
line flags. Supported runtime injection options:

- SSH agent
- `--ssh-key ~/.ssh/key`
- `--prompt-password`
- `COLLECTOR_PASSWORD`
- `COLLECTOR_PASSWORD_<USERNAME>` where non-alphanumeric characters are replaced
  with underscores and the name is uppercased

## CSV Targets

See [hosts_template.csv](docs/hosts_template.csv).

Minimum:

```csv
host,username,label,port,ssh_key,notes
linux01.example.com,auditor,linux01,22,~/.ssh/id_ed25519,prod sample
```

An optional first row can set a domain suffix for bare hostnames:

```csv
domain,example.com
host,username,label,port,ssh_key,notes
linux01,auditor,linux01,22,~/.ssh/id_ed25519,
```

## Validation

```bash
./check.sh
```

Live SSH integration tests are skipped unless these environment variables are
set:

```bash
export YMC_L_LIVE_HOST=linux01.example.com
export YMC_L_LIVE_USERNAME=auditor
export YMC_L_LIVE_SSH_KEY=~/.ssh/id_ed25519
# or:
export YMC_L_LIVE_PASSWORD=...
```

## Lab Pass/Fail Fixtures

For controlled VM testing, see
[lab_vm_validation.md](docs/lab_vm_validation.md). The helper script at
`scripts/linux_lab_state.sh` can apply reversible lab-only pass/fail states so
the scanner can be tested against known good and known weak settings.
