#!/bin/bash
set -e

echo "[+] Installing dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip
sudo pip3 install requests

echo "[+] Creating agent service..."

AGENT_DIR="$(pwd)"

cat <<EOF | sudo tee /etc/systemd/system/naxtrasoar-agent.service
[Unit]
Description=naXtraSOAR Linux Agent
After=network.target

[Service]
WorkingDirectory=$AGENT_DIR
ExecStart=/usr/bin/python3 $AGENT_DIR/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable naxtrasoar-agent
sudo systemctl restart naxtrasoar-agent

echo "[+] Agent installed and started."
