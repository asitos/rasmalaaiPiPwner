#!/bin/bash

# ensure this is the correct path to your repo!
cd /home/asitos/Projects/rasmalaaiPiAuthSim

# always pull changes first using rebase to prevent divergent branch lockouts
git pull --rebase origin main

# check if the json file was updated since the last push
if [[ -n $(git status -s captures.json) ]]; then
    echo "[+] new credentials found. syncing to upstream..."
    git add captures.json
    git commit -m "chore(telemetry): update honeypot state [skip ci]"
    git push origin main
else
    echo "[-] no new captures."
fi
