#!/bin/bash

if [ ! -f .env ]; then
    read -p "Enter your VirusTotal API Key: " API_KEY
    echo "VIRUSTOTAL_API_KEY=$API_KEY" > .env
fi

source .env
