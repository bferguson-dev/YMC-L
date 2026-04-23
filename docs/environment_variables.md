# Environment Variables

YMC-L keeps the same `COLLECTOR_*` naming shape as YMC to make a future merge
less disruptive.

## CLI Defaults

- `COLLECTOR_PROFILE`
- `COLLECTOR_FORMAT`
- `COLLECTOR_OUTPUT_DIR`
- `COLLECTOR_DOMAIN`
- `COLLECTOR_USERNAME`
- `COLLECTOR_SSH_PORT`
- `COLLECTOR_SSH_KEY`
- `COLLECTOR_CONFIG`
- `COLLECTOR_VERBOSE`
- `COLLECTOR_NO_COLOR`
- `COLLECTOR_NO_BANNER`
- `COLLECTOR_PROMPT_PASSWORD`
- `COLLECTOR_USE_SUDO`

## Connection

- `COLLECTOR_CONN_TIMEOUT`
- `COLLECTOR_READ_TIMEOUT`
- `COLLECTOR_STRICT_HOST_KEY_CHECKING`

## Evidence Thresholds

- `COLLECTOR_PASSWORD`
- `COLLECTOR_PASSWORD_<USERNAME>`

Passwords should only be injected at runtime. Do not store them in settings or
CSV files.
