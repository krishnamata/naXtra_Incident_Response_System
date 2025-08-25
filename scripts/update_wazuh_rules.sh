#!/bin/bash

REPO_DIR="/home/kali/wazuh-ruleset"

if [ -d "$REPO_DIR" ]; then
    cd "$REPO_DIR" || exit
    git pull origin master
else
    git clone https://github.com/wazuh/wazuh-ruleset.git "$REPO_DIR"
fi
