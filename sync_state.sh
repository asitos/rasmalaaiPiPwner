#!/bin/bash

# change into the project directory explicitly for cron/systemd context
cd /home/asitos/Projects/rasmalaaiPiAuthSim

# check if the json file was updated since the last push
if [[ -n $(git status -s captures.json) ]]; then
    git fetch
    git pull origin main
    echo "[+] new credentials found. syncing to upstream..."
    git add captures.json
    git commit -m "chore(telemetry): update honeypot state [skip ci]"
    git push origin main
else
    echo "[-] no new captures."
fi
