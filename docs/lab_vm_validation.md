# Lab VM Validation

Use a disposable Linux VM to validate both pass and fail scanner behavior. Start
with Ubuntu Server 24.04 LTS, then add a RHEL-like VM such as Rocky Linux 9 or
AlmaLinux 9 for package manager, firewall, SELinux, and audit differences.

## Recommended VM Flow

1. Install Ubuntu Server 24.04 LTS with OpenSSH enabled.
2. Fully patch it.
3. Create a non-root SSH user for scanning.
4. Take a hypervisor snapshot named `clean-patched-baseline`.
5. Run YMC-L against the clean VM.
6. Copy this repository or just `scripts/linux_lab_state.sh` to the VM.
7. Apply pass and fail fixture states, scanning after each state.
8. Restore from snapshot when done.

The fixture script is for lab validation only. Do not run it on production
systems.

## Pass State

On the VM:

```bash
sudo scripts/linux_lab_state.sh pass
sudo scripts/linux_lab_state.sh status
```

From the scanner workstation:

```bash
python main.py --host <vm-ip> --username <user> --ssh-key ~/.ssh/<key> \
  --profile linux_baseline --format both --no-strict-host-key-checking
```

Expected behavior: several SSH, sysctl, journald, and filesystem checks should
move toward `PASS`. Review checks may still return `WARNING` because business
authorization cannot be determined programmatically.

## Fail State

On the VM:

```bash
sudo scripts/linux_lab_state.sh fail
sudo scripts/linux_lab_state.sh status
```

From the scanner workstation, rerun the same scan.

Expected behavior: the scanner should flag findings for weak SSH settings,
selected insecure sysctl values, volatile journald storage, and a world-writable
directory without sticky bit.

## Restore

On the VM:

```bash
sudo scripts/linux_lab_state.sh restore
```

Restoring the hypervisor snapshot is still the cleanest recovery path. The
script backs up only files it edits and removes the lab artifact directory it
creates.

## Notes

- The script does not install or remove packages.
- The script does not create users.
- The script does not add passwordless sudo entries.
- The script restarts SSH if `systemctl` is available.
- Use `--no-strict-host-key-checking` only for isolated lab systems where you
  intentionally accept unknown host keys.
