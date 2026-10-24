#!/bin/sh
# yaraci lab fixture - synthetic and benign
set -e
wget -q https://artifacts.example.invalid/app.tar.gz -O /tmp/app.tar.gz
tar -xzf /tmp/app.tar.gz -C /opt/app
chmod 755 /opt/app/bin/app
systemctl restart app
