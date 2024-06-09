#!/bin/bash

# Ascii art
if ! command -v jp2a &> /dev/null; then
    echo "jp2a is not installed. Installing jp2a..."
    sudo apt update
    sudo apt install -y jp2a
fi
jp2a --color-depth=24 "Gopher.png" 

if [ ! -f .env ]; then
    read -p "Enter your VirusTotal API Key: " API_KEY
    echo "VIRUSTOTAL_API_KEY=$API_KEY" > .env
fi

source .env
