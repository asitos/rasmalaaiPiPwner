#!/bin/bash

cd /home/asitos/Projects/rasmalaaiPiAuthSim

# check if the json file was updated
if [[ -n $(git status -s captures.json) ]]; then
    echo "[+] new credentials found. staging local commit..."
    
    # 1. commit the local changes FIRST
    git add captures.json
    git commit -m "chore(telemetry): update honeypot state [skip ci]"
    
    # 2. fetch and rebase any remote dashboard updates smoothly underneath our new commit
    git pull --rebase origin main
    
    # 3. push the unified timeline to github
    echo "[+] syncing to upstream..."
    git push origin main
else
    echo "[-] no new captures."
fi
