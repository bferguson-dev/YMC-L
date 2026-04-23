# YMC-L Implementation Report

Date: 2026-04-08

## Summary

Built the first local implementation of YMC-L as a Linux-first, SSH-only,
agentless compliance evidence collector. The architecture follows the YMC
Windows scanner shape closely enough to support a future merge into a shared
multi-platform scanner:

- `main.py` CLI orchestration
- `config/settings.yaml` and named config profiles
- `connector/ssh_connector.py`
- `engine/evidence.py`, `engine/runner.py`, and self-registering checks
- `checks/linux/` platform check pack
- YAML framework profiles in `profiles/`
- HTML and JSON reporters
- CSV target loading
- local validation script and tests
- lab VM pass/fail fixture script for scanner validation

No commits were created, no remotes were configured, and nothing was pushed to
GitHub.

## Check Catalog

Implemented 103 registered Linux checks across these areas:

- System baseline and package manager inventory
- Time sync and reboot-required signal
- Account, sudo, password aging, duplicate identity records, interactive home
  directory ownership, and sensitive file permissions
- OpenSSH hardening, including authentication, forwarding, logging,
  keepalive/login timing, and weak cipher/MAC/KEX evidence
- Auditd, journald, syslog, remote forwarding evidence, logrotate, and log file
  permissions
- Firewall, automatic updates, repository signing, and disk usage
- Legacy services, file-sharing/print services, and listening service inventory
- Filesystem permissions, SUID/SGID inventory, mount review, cron path
  permissions, .netrc detection, and kernel module loading policy
- Network/kernel hardening sysctl checks
- SELinux/AppArmor, integrity tooling, PAM password/lockout signals,
  failed-login inventory, malware/EDR inventory, and core dumps
- Virtualization context and Docker privileged container review

## Framework Profiles

Added mapped-evidence profiles:

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
- `cis_ubuntu_24_04`
- `cis_almalinux_10`

All profiles now include the full 103-check Linux catalog. These profiles map
Linux-applicable, programmatically checkable technical evidence to framework
controls. They are not full manual audit/certification packages.

The two distro-specific overlays use local benchmark-style control IDs rather
than claimed official CIS section numbers. They are intended to give
Ubuntu 24.04 and AlmaLinux 10 operators a distro-specific reporting surface
without pretending the section mapping has already been fully benchmark-audited.

The overlay engine now supports profile-level policy data:

- top-level `settings_overrides`
- per-check `settings_overrides`
- per-check `status_overrides`
- per-check severity, expectation, rationale, and access metadata

This lets the same technical check stay broad in a baseline profile but become
stricter in a distro-specific overlay without forking check code.

Framework research sources used for the expansion:

- NIST SP 800-53 Rev. 5 official controls catalog:
  https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- NIST SP 800-171 official publication family:
  https://csrc.nist.gov/pubs/sp/800/171/r3/final
- FedRAMP baselines and Rev. 5 baseline posture:
  https://www.fedramp.gov/
- PCI Security Standards Council PCI DSS page and document library:
  https://www.pcisecuritystandards.org/standards/pci-dss/
- HHS HIPAA Security Rule guidance:
  https://www.hhs.gov/hipaa/for-professionals/security/index.html
- CIS Critical Security Controls v8 Navigator:
  https://www.cisecurity.org/controls/cis-controls-navigator/v8
- DoD CMMC 2.0 resources:
  https://business.defense.gov/Programs/Cyber-Security-Resources/CMMC-20/
- ISO/IEC 27001:2022 overview:
  https://www.iso.org/standard/27001

## Validation

Ran:

```bash
./check.sh
```

Result:

- Ruff lint: passed
- CLI smoke `--list-profiles`: passed
- CLI smoke `--list-checks`: passed
- Pytest: 19 passed, 1 skipped
- Pytest after overlay policy work: 21 passed, 1 skipped
- Gitleaks working-tree scan: no leaks found
- Explicit 88-column scan excluding generated/ignored runtime artifacts:
  passed

Also ran:

```bash
.venv/bin/python -m pytest -q tests/integration -m integration
```

Result: 1 skipped because no `YMC_L_LIVE_*` SSH test environment variables were
set.

## Live VM Validation

### Ubuntu VM 109

Target:

- Proxmox host: `pm01`
- VMID: `109`
- IP address: `10.0.0.190`
- Guest hostname observed over SSH: `ubuntu-server`
- Kernel observed: `Linux ubuntu-server 6.8.0-107-generic`

Setup performed:

- Took Proxmox snapshot `ymc-l-pretest-20260408100922`.
- Created dedicated test user `ymclscan`.
- Installed the local lab public key into `/home/ymclscan/.ssh/authorized_keys`.
- Added `/etc/sudoers.d/90-ymc-l-scan` for non-interactive sudo.
- Added scanner support for `--use-sudo` / `COLLECTOR_USE_SUDO` so privileged
  checks can run without root SSH.

Live scans:

- Baseline `linux_baseline`: 35 passed, 11 failed, 8 warnings, 0 errors.
- Controlled fail state `linux_baseline`: 26 passed, 20 failed, 8 warnings,
  0 errors.

After catalog expansion to 103 checks, final live scans completed with zero
scanner execution errors:

- `linux_baseline`: 74 passed, 18 failed, 11 warnings, 0 errors.
  Report: `reports/scan_20260408_104912/10_0_0_190_linux_baseline.json`
- `nist_800_53`: 74 passed, 18 failed, 11 warnings, 0 errors.
  Report:
  `reports/scan_20260408_104933/10_0_0_190_nist_sp_800_53_rev_5_linux_evidence.json`
- `cis_ubuntu_24_04`: 74 passed, 18 failed, 11 warnings, 0 errors.
  Report: `reports/scan_20260408_160856/10_0_0_190_cis_ubuntu_24_04_lts_overlay.json`
  Tightened overlay rerun: 70 passed, 22 failed, 11 warnings, 0 errors.
  Report: `reports/scan_20260408_162339/10_0_0_190_cis_ubuntu_24_04_lts_overlay.json`
- Controlled pass state `linux_baseline`: 42 passed, 4 failed, 8 warnings,
  0 errors.
- Controlled pass state `nist_800_53`: 42 passed, 4 failed, 8 warnings,
  0 errors.

Live-scan fixes made:

- Added optional sudo command wrapping in the SSH connector.
- Changed the temporary mount check to return review evidence instead of an
  execution error when `/tmp`, `/var/tmp`, and `/dev/shm` are not separate
  mounts.
- Tightened malware/EDR process inventory so the check does not match its own
  `pgrep` command.
- Changed log file permission detection to flag world-writable log files rather
  than normal Ubuntu group-write log files.
- Fixed lab SSH drop-in ordering from `99-ymc-l-lab.conf` to
  `01-ymc-l-lab.conf` because OpenSSH uses the first obtained value for
  repeated settings.

VM state after testing:

- VM 109 remains running.
- Snapshot `ymc-l-pretest-20260408100922` remains available.
- VM is currently in the lab pass fixture state.
- The dedicated `ymclscan` user and sudoers drop-in remain in place for further
  scanner testing.

### AlmaLinux VM 106

Target:

- Proxmox host: `pm01`
- VMID: `106`
- IP address: `10.0.0.105`
- Guest OS observed through guest agent: AlmaLinux 10.1

Setup and access:

- Took Proxmox snapshot `ymc-l-pretest-20260408103009`.
- Existing `bferguson-dev` SSH key access works.
- Non-interactive sudo was not available for `bferguson-dev`.
- Guest-agent attempts to create `ymclscan` or write a sudoers drop-in were
  blocked by the guest environment/permissions, so Alma validation proceeded as
  a non-sudo scan.

Fixes made from Alma validation:

- Discover `/usr/sbin/sshd`, `/usr/sbin/visudo`, and similar admin tools when
  they are not in a normal user's PATH.
- Treat failed `sshd -T` collection as a warning instead of an execution error.
- Report unreadable `/etc/shadow` as permission-limited evidence instead of a
  false pass.
- Fix reboot-required matching so `no-reboot-required` is not a failure.
- Treat Alma's stat mode `0` on unreadable shadow/gshadow files as
  permission-limited/restrictive rather than a bad mode.
- Treat `not-configured` kernel module probe output consistently.

Final live scans:

- `linux_baseline`: 54 passed, 17 failed, 32 warnings, 0 errors.
  Report: `reports/scan_20260408_104903/10_0_0_105_linux_baseline.json`
- `nist_800_53`: 54 passed, 17 failed, 32 warnings, 0 errors.
  Report:
  `reports/scan_20260408_104925/10_0_0_105_nist_sp_800_53_rev_5_linux_evidence.json`
- `cis_almalinux_10`: 54 passed, 17 failed, 32 warnings, 0 errors.
  Report: `reports/scan_20260408_160903/10_0_0_105_cis_almalinux_10_overlay.json`
  Tightened overlay rerun: 52 passed, 20 failed, 31 warnings, 0 errors.
  Report: `reports/scan_20260408_162346/10_0_0_105_cis_almalinux_10_overlay.json`

## Tried To Break It

Covered these failure and edge paths in tests:

- Missing host/CSV target returns a usage error.
- CSV target loading handles domain metadata and CLI/config precedence.
- User-specific password environment variable wins over generic password.
- Every profile check ID has a registered handler.
- Runner attaches framework mappings to results.
- Reporters write parseable JSON and HTML.
- Live SSH integration test skips unless explicitly configured.

During validation, a service-state evaluator bug was found and fixed: substring
matching for `active` could misread `inactive`. The catalog now checks exact
service-state lines for those controls.

## Parked Items

- Live SSH validation has run against VM 109 on pm01. Additional validation on
  VM 106 on pm01. Additional validation on Debian/SUSE or older supported LTS
  families would still broaden coverage.
- Framework mappings are expanded evidence mappings and still need policy
  review before being treated as final audit mapping.
- Distro-specific CIS and DISA STIG IDs should be added later for Ubuntu,
  Debian, RHEL/Rocky/Alma, and SUSE targets.
- VMware/vCenter support is intentionally parked for a later add-in or project.
- Some checks are evidence/review checks and intentionally return `WARNING`
  because authorization cannot be determined programmatically.
- VM 109 still contains lab scan access (`ymclscan`) and the current pass-state
  fixture unless reverted to the Proxmox snapshot or cleaned manually.
- VM 106 was scanned with non-sudo SSH only because non-interactive sudo setup
  was blocked; privileged evidence on Alma is therefore intentionally reported
  as warnings where the scan user cannot read it.

## Next Recommended Step

Run against one lab Linux VM with SSH key authentication:

```bash
python main.py --host <lab-host> --username <user> --ssh-key ~/.ssh/<key> \
  --profile linux_baseline --format both --no-strict-host-key-checking
```

Then review the generated JSON/HTML and tune pass/fail policy thresholds before
adding distro-specific benchmark mappings.

For controlled pass/fail testing, follow `docs/lab_vm_validation.md` and use
`scripts/linux_lab_state.sh` on a disposable, snapshotted VM.
