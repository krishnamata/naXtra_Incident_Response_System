#!/bin/bash

echo "[+] Installing dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install requests

echo "[+] Creating agent service..."
cat <<EOF | sudo tee /etc/systemd/system/naxtrasoar-agent.service
[Unit]
Description=naXtraSOAR Linux Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 $(pwd)/agent.py
WorkingDirectory=$(pwd)
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reexec
sudo systemctl enable naxtrasoar-agent
sudo systemctl start naxtrasoar-agent

echo "[+] Agent installed and started."
