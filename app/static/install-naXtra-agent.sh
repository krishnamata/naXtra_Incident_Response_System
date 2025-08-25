#!/bin/bash

SERVER_IP=$1

echo "[*] Installing naXtraSOAR Agent..."
# Simulated steps
mkdir -p /opt/naxtra-agent
echo "$SERVER_IP" > /opt/naxtra-agent/manager-ip.txt
echo "[*] Agent configured to connect to $SERVER_IP"
