# VPS Bot Hosting Manager — Two-Bot Setup

## Overview
This project provides a Telegram-based VPS bot hosting panel with a separate admin approval bot.

## Bots

| Bot | File | Purpose |
|---|---|---|
| Hosting Panel | `hosting_panel_bot.py` | User interface, ZIP upload, scanning, deployment and bot controls |
| Approval Bot | `approval_bot.py` | Admin review, approve/reject actions and pending deployments |

`script_scanner.py` is the defensive static scanner used by the hosting panel before deployment.

## Flow

1. User sends a ZIP to the hosting bot.
2. Hosting bot extracts it into a protected staging directory.
3. `script_scanner.py` scans eligible files.
4. **Clear** uploads are deployed and started through PM2.
5. **Flagged** uploads are stored as pending and sent to the admin approval bot.
6. Admin approves or rejects the deployment.
7. The hosting bot notification worker checks the database periodically and notifies the user.

## Configure

Bot tokens and admin IDs are configured in the Python files in the current version.

Before starting production use, review these settings in `hosting_panel_bot.py`:

- `BOT_TOKEN`
- `APPROVAL_BOT_TOKEN`
- `OWNER_ID`
- `ADMIN_IDS`
- `HOSTED_BOTS_DIR`
- `LOGS_DIR`
- `DATABASE_PATH`
- `MAX_ZIP_SIZE_MB`
- `MAX_BOTS_PER_USER`
- `MAX_FILES_PER_SCAN`
- `MUTE_DURATION_HOURS`
- `NOTIFY_POLL_SECONDS`

## Install / Setup

The expected project directory is:

```text
/root/HostBot2
```

Run:

```bash
cd /root/HostBot2
chmod +x setup.sh
./setup.sh
```

`setup.sh` verifies that `hosting_panel_bot.py`, `approval_bot.py`, `script_scanner.py`, and `requirements.txt` exist. It installs Supervisor/PM2, enables Supervisor, configures both bot services, and registers PM2 with systemd so saved hosted bots can be restored after reboot.

## Commands

### User-facing
Use the commands/buttons exposed by the hosting panel bot for:

- Deploy/upload a bot
- View deployed bots
- Start / stop / restart hosted bots
- View bot details and logs

### Admin
The approval bot supports:

- `/pending` — show pending deployments
- Approve — approve and start deployment
- Reject — reject a deployment

Admin-only commands should only be used by IDs listed in `ADMIN_IDS`.

## Directories

```text
/root/HostBot2/                 Project
/root/HostBot2/venv/            Python virtual environment
/root/hosted_bots/              Deployed bot files
/root/hosted_bots/inf/          SQLite database
/root/hosted_bots_logs/         Hosted bot logs
/root/HostBot2/staging_*        Temporary upload/staging directories
```

## Logs

Main Supervisor logs:

```text
/var/log/hosting_panel.out.log
/var/log/hosting_panel.err.log
/var/log/approval_bot.out.log
/var/log/approval_bot.err.log
```

Application logs:

```text
/root/hosted_bots_logs/errors.log
/root/hosted_bots_logs/notifications.log
/root/hosted_bots_logs/admin_notification_failures.log
```

The dedicated `admin_notification_failures.log` records cases where the hosting panel could not notify an admin through the approval bot.

## Requirements

Python dependencies are pinned to known compatible major/minor ranges in `requirements.txt`.

## Important security note

The current deployment architecture intentionally runs the hosting services as `root`, matching the existing project configuration. Uploaded scripts are statically scanned and are not executed by `script_scanner.py`, but static scanning cannot guarantee that arbitrary uploaded code is safe.

For production hosting of untrusted third-party code, use a separate unprivileged user/container/VM with resource and filesystem isolation.
