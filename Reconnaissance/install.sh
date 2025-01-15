#!/bin/bash

echo "[+] Starting the installation of required tools..."

# Update package lists
echo "[+] Updating package lists..."
sudo apt update -y

# Install basic tools
echo "[+] Installing basic tools (curl, wget, git)..."
sudo apt install -y curl wget git

# Install network tools
echo "[+] Installing network tools (nmap, net-tools, dnsutils, whois)..."
sudo apt install -y nmap net-tools dnsutils whois

# Install SMB enumeration tools
echo "[+] Installing SMB tools (smbclient)..."
sudo apt install -y smbclient

# Install HTTP enumeration tools
echo "[+] Installing HTTP enumeration tools (nikto, whatweb)..."
sudo apt install -y nikto whatweb

# Install wordlists
echo "[+] Installing wordlists (seclists, dirbuster)..."
sudo apt install -y seclists dirb

# Install Gobuster
echo "[+] Installing Gobuster..."
sudo apt install -y gobuster

# Install SSL analysis tools
echo "[+] Installing SSL analysis tools (sslscan)..."
sudo apt install -y sslscan

# Install SNMP tools
echo "[+] Installing SNMP tools (snmpwalk)..."
sudo apt install -y snmp

# Install subdomain enumeration tools
echo "[+] Installing subdomain enumeration tools (amass)..."
sudo apt install -y amass

# Install vulnerability scanners
echo "[+] Installing OpenVAS vulnerability scanner..."
sudo apt install -y openvas

# Final update and cleanup
echo "[+] Cleaning up and performing final updates..."
sudo apt update -y && sudo apt upgrade -y

echo "[+] Installation complete! All required tools have been installed."
