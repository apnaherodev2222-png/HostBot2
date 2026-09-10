#!/bin/bash
set -euo pipefail

cd /root/HostBot2

echo "=== 0. Required project files ==="
for required in hosting_panel_bot.py approval_bot.py script_scanner.py requirements.txt; do
    if [ ! -f "$required" ]; then
        echo "ERROR: Required file missing: $required"
        echo "Aborting setup."
        exit 1
    fi
done

echo "=== 1. Base packages ==="
apt update -y
apt install -y python3 python3-pip python3-venv nodejs npm curl supervisor

echo "=== 2. Supervisor service ==="
if ! command -v supervisorctl >/dev/null 2>&1; then
    echo "ERROR: supervisorctl is not installed."
    exit 1
fi

systemctl enable supervisor
systemctl start supervisor

if ! systemctl is-active --quiet supervisor; then
    echo "ERROR: Supervisor service is not running."
    systemctl status supervisor --no-pager || true
    exit 1
fi

echo "Supervisor is active."

echo "=== 3. PM2 ==="
npm install -g pm2

if ! command -v pm2 >/dev/null 2>&1; then
    echo "ERROR: PM2 installation failed."
    exit 1
fi

# Register PM2 with systemd so saved hosted bots are restored after reboot.
pm2 startup systemd -u root --hp /root
pm2 save

echo "=== 4. Venv ==="
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "=== 5. Directories ==="
mkdir -p /root/hosted_bots/inf /root/hosted_bots_logs
chmod 700 /root/hosted_bots
chmod 700 /root/hosted_bots_logs

echo "=== 6. Supervisor configs ==="
cat <<'EOF' > /etc/supervisor/conf.d/hosting_panel.conf
[program:hosting_panel]
directory=/root/HostBot2
command=/root/HostBot2/venv/bin/python /root/HostBot2/hosting_panel_bot.py
user=root
autostart=true
autorestart=true
startretries=5
stderr_logfile=/var/log/hosting_panel.err.log
stdout_logfile=/var/log/hosting_panel.out.log
EOF

cat <<'EOF' > /etc/supervisor/conf.d/approval_bot.conf
[program:approval_bot]
directory=/root/HostBot2
command=/root/HostBot2/venv/bin/python /root/HostBot2/approval_bot.py
user=root
autostart=true
autorestart=true
startretries=5
stderr_logfile=/var/log/approval_bot.err.log
stdout_logfile=/var/log/approval_bot.out.log
EOF

echo "=== 7. Reload + start bots ==="
supervisorctl reread
supervisorctl update

# Explicitly start them; if already running, supervisorctl reports that safely.
supervisorctl start hosting_panel
supervisorctl start approval_bot

echo "=== DONE ==="
supervisorctl status
pm2 status
